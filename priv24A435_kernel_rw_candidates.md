# PRIV-24A435 — kernel r/w candidate assessment (round 2)

Target: iOS 27.0 GM **24A435** (iPhone17,5). This file consolidates what a second,
broader pass actually produced, and answers the request for "3 ways to kernel r/w"
honestly.

**Bottom line: I did not find 3 ways to kernel r/w, and I am not going to present
three as if I had.** What follows is 3 *candidate defect paths* ranked by how close
they are to a primitive, each with the single experiment that decides it, plus the
broad sweep results that closed a lot of ground.

Fabricating three primitives would cost the campaign device runs and, worse, the
Apple-disclosure credibility its own documents repeatedly protect.

---

## 1. WHAT WAS SWEPT THIS ROUND (new ground)

| sweep | coverage | result |
|---|---|---|
| signedness class (`sxguard.py`) — sign-extended value + **signed** guard | **300 kexts + 9 dylibs + 135 extracted framework dylibs** | 1,928 (k) + 1,900+ (dy) raw candidates; strict index-shape filter → **16 in frameworks**, **1 in the kernel/media stack** |
| apfs | full kext | 246 narrow hits, dominated by one Unicode case-folding sentinel idiom (benign, §4) |
| lifs / tmpfs | full kext | 4 / 0 raw candidates — nothing |
| `AppleFSCompressionTypeZlib` (decmpfs) | full kext, target-side read | overflow guard is **correct** (§4) |

New tooling: `kcoll.py` (whole-collection harness), `sxguard.py` (+ control
self-check), `tri.py`, `xr.py`, `prodx.py` (zero-result self-check), `findimm.py`,
`strref.py`, `checksym.py`.

Coverage limit, stated plainly: only **135** of the ~1,500 shared-cache images were
extracted (`ipsw dyld extract` was killed when its parent shell exited; `BACKGROUND`
is unavailable and the extract needs >10 min). The framework sweep is therefore a
**sample**, not the full userspace. Also: **no HFS kext exists** in this collection —
only `apfs`, `lifs`, `tmpfs` and the zlib compression kext, so "hfs" is not a surface
on 27.0 GM.

---

## 2. CANDIDATE 1 — `AppleAVE2`: loop bound = signed product of two signed bytes

**KERNEL kext. Daemon-reachable** (AVE2 is the encoder the campaign already drives
through `videocodecd`; entitlement `aocp-client`).

Function `0xfffffff00886b170`, verbatim:

```
0x8886b174  ldr   x8, [x0, #8]        ; s = x0->[8]
0x8886b178  ldrsb w9,  [x8, #0x18c]   ; a = (int8) s->[0x18c]
0x8886b17c  ldrsb w10, [x8, #0x18d]   ; b = (int8) s->[0x18d]
0x8886b180  mul   w9, w10, w9         ; n = a * b      <-- 32-bit SIGNED product
0x8886b184  subs  w10, w9, #1
0x8886b188  cset  w0, gt
0x8886b18c  b.lt  0x8886b1d0          ; n < 1 -> return
0x8886b194  mov   x12, x9             ; count = n
loop:
0x8886b1bc  ldr   w14, [x1, x11, lsl #2]  ; *** x1[i] -- read, i in [0, n) ***
0x8886b1c4  add   x11, x11, #1
0x8886b1c8  subs  x12, x12, #1
0x8886b1cc  b.ne  loop
```

`n` is the signed product of two **signed bytes**, and **nothing relates `n` to the
length of `x1`**. The guard `n >= 1` only rejects the negative products. Two negative
inputs (`0x80`, `0x80`) give `n = 16384` — a 64 KB over-read of the caller's array.

* **Proven**: the arithmetic, the absence of any size relation, the single caller
  (`0xfffffff00886bf0c`, `mov x0, x19; mov x1, x21`).
* **Not proven**: the provenance and legal range of `s->[0x18c]`/`s->[0x18d]`, and how
  the caller sizes `x21`.
* **One question decides it**: trace `x21` at the caller and the writers of
  `+0x18c`/`+0x18d`. If the bytes can exceed `0x7f` while the caller sizes the array
  from a *different* quantity, this is a kernel OOB read — the campaign's class #3
  ("two computations that diverge"), in the kext with the largest hardening delta of
  the cycle.

**Why it is the strongest kernel-side candidate**: it is a *read* bound derived by
multiplication of attacker-shaped bytes, which is a shape the campaign has not
previously chased (its four refutations were all index-vs-array-capacity).

## 3. CANDIDATE 2 — MV-HEVC signed index (daemon, not kernel)

`AVD.videodecoder`, `CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb(int)`
(`0x22a382dfc`). Full detail in `priv24A435_mvhevc_signed_index.md`.

Guard is `cmp w8, w9` + **`b.le`** (signed) — so every negative value passes — and the
value is returned from an unbounded pointer-table load `ldr x0, [x9, w8, sxtw #3]`.
The array it comes from is **provably 64 entries** (`_parseHevcSps` copies with a
hard-coded `#0x40`). It is the **only** hit of its shape in the whole sweep, and it is
the class a producer check *cannot* rescue.

Ceiling: **userspace daemon**. Not kernel r/w.

## 4. THINGS THAT CAME BACK CLEAN (checked, do not redo)

* **`AppleFSCompressionTypeZlib`** (decmpfs, file-op reachable, 98 KB, previously
  unaudited): the "add overflow" site is a **correct** 64-bit signed-overflow idiom
  (`asr` sign extraction + `adc` + `tbnz #0`, `0xfffffff008b9d4b0`–`0xfffffff008b9d4c0`).
  The kext carries real validation ("resource fork is too small", "invalid resource
  map", "decmpfs xattr size should be greater than", "vecTotal is too big", "invalid
  offset"). No defect found on a read pass. **Not** a candidate.
* **apfs's 246 narrow hits** are dominated by `sxth` + `cmn w8, #7, lsl #12` (`cmp` vs
  `-28672`) — a Unicode case-folding sentinel test, not a bound. The surrounding code
  uses the clang **index-scaling** guard (`cmp x10, w10, sxtw` + `movk #0x2bad` +
  `csel`) that the campaign already identified as *not* a bounds check. Benign.
* **`lifs` / `tmpfs`**: 4 / 0 raw candidates. Nothing.
* **Frameworks** (`--class idx`): GeoServices (6), libicucore (4), IDSFoundation,
  CoreGraphics, libswiftCore, CoreML, CoreUtils, Espresso. All **userspace**; libicucore
  and ImageIO are the most app-reachable. These are candidate *userspace* bugs, not
  kernel r/w paths — they would at most be a same-process compromise.

## 5. THE HONEST ANSWER TO "3 WAYS TO KERNEL R/W"

To be a kernel r/w path a candidate needs three things, and the campaign's own record
says it has **none** of them for 24A435: (a) an app-reachable memory-safety bug,
(b) an info leak, (c) a way past PAC/KTRR/PPL. `REPORT_27_0_CVE_HUNT.md` already states
the top-level verdict — *"no app-reachable memory-corruption vulnerability was proven
in 24A435"* — and this round did not overturn it.

What I can say with evidence:

1. **Candidate 1 (AVE2 signed-product bound)** is the only new **kernel** lead with an
   identified missing invariant. It is one trace away from a verdict.
2. **Candidate 2 (MV-HEVC)** is fully characterised but is daemon-side.
3. **Frameworks** are a large, only-sampled userspace surface; a bug there is not kernel.

Anything stronger than that would require the remaining ~1,400 shared-cache images
extracted and swept, plus the runtime experiments (row-K-style crafted bitstreams) —
i.e. real device time, which is the campaign's actual bottleneck, not more static grep.

---

## 6. THE `_dmaReferences` LINE, RE-EXAMINED (the one kernel *primitive-genre* lead)

`priv24A435_dma_refcount_leak.md` leaves exactly one unrun, bounded experiment: the
note swept for **atomics** on `descriptor+0x34` but never for **reads** of it — and a
UAF requires a *consumer* that treats `_dmaReferences == 0` as "no DMA in flight" and
acts on it. `field_sweep.py` covered the atoms; nothing covered the reads.

That is the single highest-value unrun check on the table for this line, because it is
the difference between "counter-integrity defect" (current honest label) and a real
use-after-free. It is a bounded collection-wide sweep of the same kind already built
here (`prodx.py` extended to loads). **Recommended next.**

---

## 7. REPRODUCE

```
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --control      # must PASS
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --class idx    # 1 hit
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --class mul    # 1 hit (AVE2)
/opt/homebrew/bin/python3 analysis/priv24A435/sxguard.py --dir /tmp/ds24/dy --class idx
/opt/homebrew/bin/python3 analysis/priv24A435/tri.py com.apple.driver.AppleAVE2 0xfffffff00886b170 0x20 0x60
```
