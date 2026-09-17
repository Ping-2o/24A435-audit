# PRIV-24A435 — a signed, unbounded index in the MV-HEVC decoder (AVD.videodecoder)

Target: iOS 27.0 GM **24A435** (iPhone17,5). Binary:
`/Users/pauyedin/24A435__iPhone17,5/dylibs/AVD.videodecoder` (arm64e, **6223 symbols** — full
symbol table, so every function below is named by Apple's own symbol, not a guess).

**Method**: a new whole-firmware sweep (`sxguard.py`) for the defect class the campaign
identified as productive but never swept — **"a check that is present but wrong"**
(`PRIV_HUNT_24A435.md` §2E, class 1). Specifically: a value that is *narrowed or
sign-extended* from a field, then guarded by a **signed** compare. This is the exact shape
Apple itself shipped a bug in this cycle (`_dmaReferences`: `sxth` → `cmp #0x4000` → `b.lt`),
and it is the one class that a producer-side check **cannot** rescue, because the guard
itself is the wrong shape.

The sweep scanned **309 binaries** (300 kexts + 9 dyld-cache dylibs), produced 1928 raw
candidates, and reduces to **exactly one** hit of the dangerous shape — *sign-extended value
loaded from memory, guarded by a signed compare, then used as an index*. This is it.

---

## 0. HEADLINE

`CAVDMvHevcDecoder` (the **multiview / MV-HEVC** decoder path in `AVD.videodecoder`) indexes a
**64-byte** per-view array with a value that is

1. **never bounds-checked against 64**, and
2. **sign-extended**, so any value with the top bit set becomes a *negative* offset;

and the byte it reads is then used, again **unbounded and sign-extended**, as an index into
pointer tables — in one place returning the loaded pointer straight to the caller.

Verdict: **a real "check present but wrong" defect with a clearly identified missing bound.**
Whether the input can actually reach the bad values is **not proven** (§5) — it needs a
crafted MV-HEVC bitstream, and the campaign's own track record is four use-site candidates
refuted by producer checks. This one is different in kind (§4): the guard is *wrong*, not
absent, so the usual refutation does not apply.

---

## 1. THE SITE — `CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb(int)`

`0x22a382dfc`. Called from `CAVDMvHevcDecoder::mvhevcOutputBumping(...)` (`0x22a3817d4`) at
three sites.

The tail of the function, verbatim:

```
0x22a382f08  ldr   x9, [x19, #0xec0]        ; x9  = this->vpsState
0x22a382f0c  ldr   x8, [x9, #0x1160]        ; x8  = vpsState->pArrayObj   (the 0xf30 object, S3)
0x22a382f10  add   x8, x8, w20, sxtw        ; x8 += SEXT(arg)            <-- OFFSET, sign-extended
0x22a382f14  ldrsb w8, [x8, #0x243]         ; w8  = (s8) *(x8 + 0x243)   <-- VALUE, sign-extended
0x22a382f18  mov   w10, #0x1118
0x22a382f1c  add   x9, x9, x10              ; x9  = vpsState + 0x1118
0x22a382f20  ldrsb w9, [x9]                 ; w9  = (s8) vpsState->[0x1118]   (a threshold byte)
0x22a382f24  cmp   w8, w9
0x22a382f28  b.le  #0x22a382f40             ; *** SIGNED compare - every NEGATIVE w8 passes ***
0x22a382f2c  ... epilogue ... retab         ; (w8 > w9) -> return without loading
0x22a382f40  add   x9, x19, #0xc08          ; x9  = this + 0xc08   (a pointer table)
0x22a382f44  ldr   x0, [x9, w8, sxtw #3]    ; *** x0 = table[w8] - NO bound on w8 - RETURNED ***
0x22a382f48  ... epilogue ... autibsp/retab
```

Two independent unchecked, sign-extended uses:

* **the offset** (`w20`, sign-extended at `0x22a382f10`) into the array at `+0x243`;
* **the loaded byte** (sign-extended by `ldrsb` at `0x22a382f14`) as an index into the
  pointer table at `this+0xc08`, whose result is **returned** to the caller.

The only guard is `w8 <= w9` with a **signed** `b.le`. Written that way it is an *upper*
bound only for non-negative values; the entire negative half of the range passes straight
through to `ldr x0, [x9, w8, sxtw #3]`, which reads `8 * |w8|` bytes **before** the table and
returns whatever pointer is there.

## 2. THE ARRAY IS EXACTLY 64 ENTRIES — and nothing checks the index against it

The same `+0x243` expression appears in `CAVDMvHevcDecoder::mvhevcOutputBumping`
(`0x22a3818c0`) and in three sibling functions, always with the same shape:

| site | function | use of the byte |
|---|---|---|
| `0x22a3818c4` | `mvhevcOutputBumping` | `ldrsb x11` → `x11*28` → index `[x22+0x200]` entry table |
| `0x22a381910` | `mvhevcOutputBumping` | `ldr x11, [x12, x11, lsl #3]` → index `[x22+0x208]` pointer table |
| `0x22a380d48` | `deriveMvHevcOutputControlFlags` | `ldrsb x9` → `x9*28` → `ldrsh [x8, x10, #0x16]` |
| `0x22a381120` | `decodeMultiViewPictureOrderCount` | `ldrsb x9` → `add` → `ldrb` |

**None of them compares the value against anything except the signed threshold.** There is no
`cmp #0x40`, no `and #0x3f`, no `ubfx`.

The array's true capacity is proved, not inferred, by the function that fills it —
`HEVC_RBSP::parseVPS` allocates the object, and `_parseHevcSps` copies the array with a
**hard-coded count of 0x40**:

```
_parseHevcSps  @0x22a369f88
0x22a369f88  add  x10, x8,  #0x243      ; src  = spsObj + 0x243
0x22a369f8c  mov  w11, #0x40            ; *** COUNT = 64 ***
0x22a369f90  ldrb w12, [x10, x9]
0x22a369f94  strb w12, [x20, x9]        ; dst  = obj + 0x243
0x22a369f98  add  x9, x9, #1
0x22a369f9c  subs x11, x11, #1
0x22a369fa0  b.ne #0x22a369f90          ; loops exactly 64 times
```

So `obj+0x243` is a **64-entry byte array**, filled from SPS-derived data, and the index into
it is a raw sign-extended byte. `idx == 0x80..0xFF` reads *before* the array;
`idx > 63` reads past it.

### 2.1 The object is big enough to hide the offset overrun — worth stating plainly

`HEVC_RBSP::parseVPS` (`0x22a4643f8`) allocates the object with a **0xf30 (3888)-byte**
allocation and zeroes it:

```
0x22a4643f0  mov  w0, #0xf30
0x22a4643f8  bl   #0x2300ddfe0          ; alloc(0xf30)
0x22a4643fc  str  x0, [x19, #0x1160]    ; vpsObj->pArrayObj = it
0x22a464408  bl   #0x2300c6c80          ; zero it (size 0xf30)
```

Because `0x243 ± 128` stays inside `[0, 0xf30)`, the *offset* overrun alone does not leave
the allocation — it lands in neighbouring fields of the same object. That weakens the
"offset" half to an intra-object read. **The value half is the sharper one**: the byte read
is then used as an index into `[obj+0x200]` / `[obj+0x208]` / `this+0xc08`, and *that* read
is not confined to the object (it is `base + value*28` / `+value*8`, signed).

## 3. WHERE THE INDEX COMES FROM

`this+0xbd8` is a **byte** with two writers:

```
CAVDMvHevcDecoder::VADecodeFrame+0xd0  @0x22a37fddc
0x22a37fdcc  ldr   x8, [x0, #0x920]      ; x8 = this->parentObj
0x22a37fdd0  mov   w9, #0x1624
0x22a37fdd4  add   x8, x8, x9
0x22a37fd d8 ldrb  w8, [x8]              ; w8 = BYTE (0..255) at parentObj+0x1624
0x22a37fddc  strb  w8, [x0, #0xbd8]      ; this+0xbd8 = that byte   <-- NO RANGE CHECK

CAVDMvHevcDecoder::checkNewPocResettingPeriod+0x88  @0x22a380bf0
0x22a380bec  mov   w9, #1
0x22a380bf0  strb  w9, [x8, #0xbd8]      ; this+0xbd8 = 0 or 1   (bounded)
```

The first writer copies an unvalidated **byte** (`ldrb` → 0..255, stored back with `strb`)
into a field that every consumer then reads with **`ldrsb`**. That is the sign-extension
boundary: a source byte `>= 0x80` becomes a negative index everywhere downstream.

`this+0x920` is set in the constructor `CAVDDecoder::CAVDDecoder(void*, unsigned int)`
(`0x22a348360`, `str x1, [x0, #0x920]`) — an object injected by the caller; the byte it reads
at `+0x1624` has **zero displacement writers** in this binary (consistent with the
campaign's "arrives by bulk copy" pattern — it is not produced by a kext store).

## 4. WHY THIS IS NOT THE USUAL FOUR-REFUTATION CANDIDATE

`PRIV_HUNT_24A435.md` §2E records four "unguarded index/use-site" candidates, each refuted by
a **producer-side** check (`cmp w8,#4` in the setter; `(u32)(count-1) <= 7` in the plugin
setter; the byte-LUT whose own width bounds it). The rule that emerged: *in this codebase the
bound is enforced at the producer, so a use-site "missing cmp" sweep yields false positives.*

This finding is a different situation, and that is the point:

* the guard **exists** (`cmp w8, w9`), so the usual "is there a producer check?" question does
  not apply — the producer could bound the byte to `0..255` and the guard would *still* admit
  every value `>= 0x80`, because it is a **signed** `b.le`;
* this is precisely Apple's own bug class from this cycle (`_dmaReferences`, where a 16-bit
  counter sign-extended before a signed `b.lt`).

The missing artefact is not a `cmp`; it is the *signedness*. A fix is a one-instruction change
(`b.hi`/`and #0x3f`), which is what makes it a defect rather than a design.

## 5. WHAT IS **NOT** PROVEN (be honest)

1. **That the source byte can actually reach `>= 0x80` (or `> 63`).** `this+0xbd8` copies
   `parentObj+0x1624`, which has no displacement writer; the campaign's own lesson is that a
   field with no displacement writer is filled by a bulk copy upstream. Until that upstream is
   resolved (or a crafted MV-HEVC bitstream demonstrably drives it), the bad values are
   *plausible*, not *demonstrated*.
2. **That `w9` (the threshold at `vpsState+0x1118`) is non-negative.** If it were always
   negative the signed compare would actually reject negatives — but a threshold byte at
   `+0x1118` of a VPS object is far more likely a view/sub-DPB count (`>= 0`), in which case
   the negative half passes.
3. **That the OOB-loaded pointer is dereferenced in a way that yields a primitive.** At
   `0x22a382f44` it is returned; the three call sites in `mvhevcOutputBumping` show it flowing
   into further table walks (`0x22a381b3c`: `ldr x0, [x24, w20, uxtw #3]` then `bl`), but the
   full consequence is not traced here.
4. **Reachability from an unentitled app.** This is a *daemon* component (`videocodecd` loads
   `AVD.videodecoder`). The campaign's row K established the app → VideoToolbox → videocodecd
   path for H.264; the **MV-HEVC** entry (`CAVDMvHevcDecoder`, spatial/multiview video) is not
   something row K exercised, and whether VT exposes it to a plain app needs checking.

## 6. HONEST CEILING

**This is a daemon-side (userspace) defect, not a kernel one.** It does not by itself give
kernel read/write, and it should not be described as a kernel bug. Its value is:

* it is a **new, concrete, precisely-located defect in shipped 24A435**, in a component
  (MV-HEVC / multiview) that the campaign has not previously audited;
* it is the **only** hit of its shape in 309 binaries, from a control-validated sweep — so the
  search space for this class is now genuinely closed, and that is a reusable result;
* it is the class that is *not* disproved by the producer rule that killed the last four
  candidates.

If the source byte turns out to be bounded `0..63`, this degrades to a hardening note (a
signed compare where an unsigned one is required), which is still reportable.

## 7. NEXT STEP (one question)

Resolve `parentObj+0x1624` in `CAVDDecoder` (`this+0x920`): who fills that object, and is the
byte at `+0x1624` an index/count with a range that can exceed 63 (or 127)? That is a single
bounded question, and it decides candidate → bug or candidate → hardening note.

---

## 8. ARTIFACTS

| file | purpose |
|---|---|
| `analysis/priv24A435/kcoll.py` | whole-collection Mach-O harness (all 300 kexts + dylibs); VA translation, section/string access |
| `analysis/priv24A435/sxguard.py` | **the sweep.** Sign-extend → signed-compare detector, raw-encoding based, with a `--control` self-check against the known `_dmaReferences` bug and classes `idx`/`mul`/`narrow`/`mem` |
| `analysis/priv24A435/tri.py` | disassembly window around a VA in a named binary |
| `analysis/priv24A435/xr.py` | direct caller search + symbol resolution |
| `analysis/priv24A435/prodx.py` | displacement store/load producer tracer (with a zero-result self-check) |
| `analysis/priv24A435/findimm.py` | locate `add rD, rN, #imm` sites and their context (how an indexed base is built) |

Reproduce:
```
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --control
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --class idx
```

### Method notes (two traps hit and fixed in this session — both are the campaign's own lessons)

1. **Capstone register IDs are not encoding register numbers.** `creg()` must map through
   `MD.reg_name()`; comparing `op.reg` against `(w>>5)&0x1f` silently misses everything.
2. **`ARM64_OP_MEM` is `3`, not `6`.** Hard-coding the operand-type literal made `prodx.py`
   return a confident **zero** for every displacement — the exact "never trust an empty
   result" failure this project's notes warn about. It now refuses to report when it decodes
   zero memory-operand stores.
3. A use-site scan must **stop at a redefinition** of the register, or an unrelated later use
   of the same architectural register is mis-attributed to the guarded value (this produced
   a false kernel hit at `0xfffffff00ac09f54` that the fix removed).
