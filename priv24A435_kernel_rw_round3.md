# PRIV-24A435 ROUND 3 — full shared-cache sweep, and two kernel candidates audited to a verdict

Target: iOS 27.0 GM **24A435** (iPhone17,5). Kexts at `/Users/pauyedin/24A435__iPhone17,5/kexts`,
shared cache at `.../24A435__iPhone17,5/dyld_shared_cache_arm64e` (40 slices, 6.8 GB).

Reproduce: `ipsw dyld extract dyld_shared_cache_arm64e --all -o /tmp/ds24/dy`, then
`python3 analysis/priv24A435/sxguard.py --dir /tmp/ds24/dy --class narrow`.

---

## 0. HEADLINE — no kernel r/w, no LPE, no UAF proven this round

Stated plainly because the campaign's credibility depends on it: **this round did not produce a
kernel read/write primitive, a privilege escalation, or a use-after-free.** What it did produce
is (a) a 117× coverage increase over the previous sweeps, (b) the closure of one defect class
across that new corpus, and (c) two *verdicts* on previously-open kernel candidates — one of
which (the non-atomic reset) is now **defused**, with the disassembly evidence below.

Five candidate classes have now been examined to a verdict in the LINE C work and **four
closed**. That rate of closure is itself the finding: on 24A435 the kernel-side surfaces this
campaign can reach are, so far, honestly defended.

---

## 1. THE COVERAGE GAP WAS THE REAL BLIND SPOT (9 → 1056 images)

The previous LINE C sweeps ran over **300 kexts + 9 dylibs**. The 9 dylibs were the *only*
shared-cache images ever carved. The cache contains ~1,500 images. Every framework — i.e. every
library an app can actually link and call — was unswept.

This round carved **1056 images** (`/tmp/ds24/dy`, 979 under `System/Library`, 74 under
`usr/lib`), including `IOKit`, `IOGPU`, `CoreGraphics`, `VideoToolbox`, `libxpc`,
`libsqlite3`, `libicucore`, `JavaScriptCore`, `WebCore`, `CoreML`.

The extraction was twice killed by a 600 s cap; it reached 1056 of ~1500. **The remaining ~450
are still unswept** — the one honest coverage caveat on everything below.

## 2. CLASS CLOSURE — the sign-extended-index defect class

Class: *a value sign-extended from memory, guarded by a **signed** compare, then used as an
index.* This is the shape Apple itself shipped a bug in this cycle (`_dmaReferences`: `sxth` →
`cmp #0x4000` → `b.lt`), and it is the one class a producer-side bound **cannot** rescue,
because the guard itself is the wrong shape (`PRIV_HUNT_24A435.md` §2E class 1).

Sweep (`sxguard.py`, raw-encoding based, control-validated against the known `_dmaReferences`
site, and it refuses to report if the control fails):

| corpus | binaries | raw candidates | `narrow` + index + memory-sourced |
|---|---|---|---|
| kexts + 9 dylibs (prior) | 309 | 1928 | **1** |
| **full shared cache (this round)** | **+1056** | — | **1 (the same one)** |

So across **~1,365 binaries** the dangerous narrow-index shape occurs **exactly once** —
`AVD.videodecoder 0x22a382f14` (`CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb`), the
finding in `priv24A435_mvhevc_signed_index.md`. That class is now closed as a search space.

### 2.1 The top framework candidates, triaged (all benign)

The high-scoring narrow hits in the new corpus were examined individually. Three representative
ones, and why each is benign:

* **CoreGraphics `0x183d0d5ec`** (score 11) — `ldr x8,[x2,#0x88]; ldrsb w9,[x8]; cmp w9,#0`.
  This is a **C-string loop** (`while (*p)`) — the `ldrsb` is a byte fetch, `cmp #0` is the
  null test. Not an index.
* **ProofReader `0x1cebf17bc`** (score 10) — `add w8,w19,#1; sxtb w19,w8; cmp w19,#5`. A
  **loop counter** in a signed byte; the sign-extension is incidental.
* **AudioCodecs `0x1bccb4c04`** (score 10) — `sxth x20,w19; cmp x20,x8`. A sign-extended
  **distance/length compare**, not a table index.

This is a useful negative result: the class's population in real code is dominated by
(1) `ldrsb` + `cmp #0` string loops, (2) signed loop counters, (3) signed length compares —
which is exactly why the AVD hit stands out, and why a *narrow* (8/16-bit) filter is required:
the looser `ldrsw` (32-bit) filter returns 72 hits, all ordinary count loops.

## 3. `_dmaReferences` — one candidate RESOLVED REAL, one DEFUSED

Two open kernel questions were carried into this round.

### 3.1 RESOLVED REAL: the consumer exists

`priv24A435_xnu_refcount_findings.md` §6 concluded there was **no consumer** that treats
`_dmaReferences == 0` as "no DMA in flight", and that this is what made the line empirically
dead. That is **refuted** — see `priv24A435_dmaref_consumer.md`: the field is read at
`0xfffffff00b343bdc` and the non-zero path is the fatal assert
**`complete() while dma active @ IOMemoryDescriptor.cpp:5331`** (file offset `0x70c1db9`,
`adrp #0xfffffff0070c1000`, line 5331). So the counter *is* a safety gate: `refs == 0` is
interpreted as "safe to complete".

### 3.2 DEFUSED: the non-atomic reset cannot fire with references live

`priv24A435_dma_refcount_leak.md` §6.3 raised the `strh wzr, [x19, #0x34]` at
`0xfffffff00b346888` as the *cheaper* route to `refs == 0` with live references — "no 32,768-call
climb". **That route is closed.** Two facts:

**(a) The reset is reachable only by fall-through.** A raw-encoding scan of all of
`__TEXT_EXEC` for `b` and `b.cond` targeting `0xfffffff00b346888` returns **zero sites**. The
only way in is the immediately preceding instruction:

```
0xfffffff00b34687c  and   w20, w27, #0xffff7fff
0xfffffff00b346880  str   w20, [x19, #0x20]     ; command flags
0xfffffff00b346884  str   x4,  [x19, #0x70]
0xfffffff00b346888  strh  wzr, [x19, #0x34]     ; _dmaReferences := 0
```

**(b) Both entrances are pre-teardown.** `0xfffffff00b346830` is reached from exactly two
places in the prepare function (`0xfffffff00b346638`):

```
0xfffffff00b346704  ldrb  w8, [x19, #0x8c]          ; bit0 = "already prepared"
0xfffffff00b346708  tbz   w8, #0, #0xfffffff00b346780
0xfffffff00b346780  mov   w8, #1                    ;  <-- FIRST prepare
0xfffffff00b346784  strb  w8, [x19, #0x8c]          ;      set the flag, no teardown needed
0xfffffff00b34678c  b     #0xfffffff00b346830       ;      -> reset (refs are 0 by construction)
              ...                                          <-- RE-prepare
0xfffffff00b34675c  ldr   x1, [x19, #0x60]          ;      old memory descriptor
0xfffffff00b346774  bl    #0xfffffff00b10d38c       ;      release it
0xfffffff00b3467c4  ...  virtual [x16+0xb8] on [x19+0x18]  ;      complete/release
0xfffffff00b34682c  mov   x4, x20
0xfffffff00b346830  orr   w8, w5, #0x800            ;  <-- common tail
```

On the **first** prepare the flag is clear, nothing is mapped, and `refs == 0` is true by
construction. On a **re**-prepare the old mapping is released **before** the tail is reached.
There is no path that zeroes the counter while a mapping from the previous prepare is still
outstanding — so the invariant the `op 6` release gate (`0xfffffff00b34571c`) and the map
worker's fast path both depend on is **not** broken by this store.

**Correction owed to the earlier note.** `priv24A435_dma_refcount_leak.md` §6.3 describes this
store as *"if this reset can run while references are outstanding"* and ranks it as the stronger,
cheaper candidate. It cannot, and it is not. The remaining defect on this line is the
**signed-compare + post-increment** shape in `dmaCommandOperation` (findings §3), which needs the
drift/wrap route — 65,536 prepares on one `IODMACommand`. That is a *runtime* question, not a
static one, and it is the top-ranked lead in §5.

### 3.3 The `_dmaReferences` wrap needs 65,536 prepares — and the only app-openable producer recreates its command

The surviving kernel defect on the `_dmaReferences` line is the signed-compare + post-increment
shape (findings §3): reaching `refs == 0` with a pin live requires **65,536 prepares on one
`IODMACommand`**. Whether any app-reachable path can do that is the whole question, and the bind
site answers a large part of it.

`priv24A435_dma_producer_reach.md` establishes that **`AppleM2ScalerCSCDriver` is the only
producer that is both gate-signal-free and app-facing** (one bind site, `0xfffffff0090d0470`).
That function is:

```
0xfffffff0090d04b8  bl    #0xfffffff009068d6c      ; (0x10b, 0x1ce4, 0, x25, 1) -- alloc/init
0xfffffff0090d04c4  bl    #0xfffffff0090d06f8
0xfffffff0090d04c8  str   x0,  [x20]               ; *** store the IODMACommand into an OUT-POINTER ***
0xfffffff0090d04d0  ldr   x16, [x0]
0xfffffff0090d04e0  ldr   x8,  [x16, #0x88]!       ; vtable slot 0x88
0xfffffff0090d04e8  mov   w2,  #1                  ; cache = true
0xfffffff0090d04ec  movk  x16, #0xb91, lsl #48     ; *** diversity 0xb91 ***
0xfffffff0090d04f0  blraa x8,  x16               ; *** IODMACommand::setMemoryDescriptor ***
```

Two things follow. First, this independently **confirms the campaign's producer identification
from the driver side**: the bind site really is a call into vtable slot `0x88` with PAC diversity
`0xb91`, i.e. `IODMACommand::setMemoryDescriptor(desc, cache=true)`, and the descriptor comes in
as `x25` — a direct argument, so it is **not** a per-call wrapper with a cached command. Second,
the command is **produced inside this function and returned through the caller's out-pointer**
(the `str x0, [x20]`), not fetched from a long-lived field on the accelerator object. On a caller
that invokes this helper once per transfer — which the surrounding call site
(`bl #0xfffffff0090d046c` at `0xfffffff0090d039c`) is consistent with — that is **one fresh
`IODMACommand` per prepare**, so the counter cannot accumulate and the 65,536-prepare requirement
is not met.

**This materially weakens lead #1 and it is the most important result of this round's kernel
work.** The follow-up trace settles the shape: in the enclosing function
(`0xfffffff0090d02d0`-ish, containing the call site `0xfffffff0090d039c`) the out-pointer is
**`mov x24, x3` — the caller's own argument 3** — forwarded unchanged as the bind helper's `x3`:

```
0xfffffff0090d0300  mov  x24, x3                 ; out-ptr = THIS function's arg 3
0xfffffff0090d0390  mov  x3,  x24                ; ... forwarded to the bind helper
0xfffffff0090d039c  bl   #0xfffffff0090d046c     ; -> str x0,[x20] + slot 0x88 / 0xb91
```

and the bind helper writes the newly created command to `*x3` with **no "already present"
test** — the sequence is alloc → init → `str x0, [x20]` unconditionally on the success path,
with no prior `ldr x8, [x20]; cbnz x8, out` reuse check. So the command is **not** cached on the
accelerator object at this layer.

Therefore: the counter is per-`IODMACommand`, one prepare is issued per freshly-created command,
and the **65,536-prepare wrap is not reachable through the only app-openable producer**. Lead #1
is recorded as **closed on the reachable path** (evidence, not proof: a caller above this
function could still reuse a command *and* skip the bind helper, which would need a separate
producer trace). Note this does not disturb the *existence* of the defect — the signed compare
and post-increment in `dmaCommandOperation`, and the `complete() while dma active` consumer, are
all still real. It is a reachability closure, which is the honest currency here.

## 4. AVD patch engine — already closed; the chunker residual is NOT closed

`priv24A435_avd_alloc_vs_bound.md` records the FW-command patch engine as CLOSED on GM
(three chained invariants pin the bound to a compile-time per-codec constant). Re-read this
round; the verdict stands.

Its §6 residual lead 1 (the boundary splitter) was pursued and **not** closed. What was
established:

* the function at `0xfffffff0086aeb58` **copies** a `0xb0`-stride descriptor in from its arg2
  (`ldp/stp q0,q1` over `sp+0x40..0xf0`, after a `0x2c0`-byte zero-fill = a **4-entry** array,
  `0x2c0 / 0xb0 = 4`); it does not build chunk offsets itself;
* it delegates to a thunk `0xfffffff00868b294` → `b 0xfffffff008689500`, which is the generic
  **allocate-and-round-up** routine (`len < 0x1cc00001`; `add x9,len,block; sub #1;
  neg x8,block; and x28,x9,x8` = align up to the device block size), i.e. the *allocation* side,
  not the per-chunk size field;
* the per-chunk size reduction is therefore in a third site not yet reached.

So residual lead 1 remains a **hypothesis**, not a finding. What would settle it is one pass
finding the `str` that writes each chunk descriptor's size field and showing whether it is
`len` or `len - chunk_offset`. Left open deliberately rather than guessed.

## 5. THE LEADS, RANKED, WITH THE SINGLE EXPERIMENT FOR EACH

Everything below is honest about being unproven. Ranked by (probability × impact).

1. **`_dmaReferences` wrap → `complete()` gate bypass → teardown with DMA live (kernel UAF).**
   *Static status:* the increment is post-increment and unconditional; the guard is
   `sxth` + signed `b.lt #0x4000`, so `[0x8000, 0xffff]` **pass** and the work path runs with a
   negative-signed counter; the decrement reads the field **unsigned** (`ldrh`), so the two
   directions compound. The consumer (`complete() while dma active`) is proven to exist (§3.1),
   and the non-atomic reset route is defused (§3.2).
   *Blocking:* a caller that issues **65,536 prepares on one `IODMACommand`**. §3.3 shows the
   only app-openable producer creates its command inside the bind helper and writes it to an
   out-pointer with no reuse test, i.e. one fresh command per prepare — so this lead is
   **closed on the reachable path**. It is listed first only because it is the one lead whose
   *consumer* is already proven; the defect itself stands as a hardening item.
   *Experiment (downgraded):* no device run. A caller-above trace would be needed only to
   re-open it against some other producer.

2. **AVD boundary-splitter per-chunk size field (kernel heap OOB write).**
   *Static status:* hypothesis (§4); the rest of the chain is triple-checked.
   *Experiment:* static only — one pass to locate the chunk-descriptor size store. Cheap, and if
   it shows `size = len` while `ptr = base + off`, it is the campaign's first real kernel write.

3. **MV-HEVC signed index (`AVD.videodecoder`, daemon-side).**
   *Static status:* the only instance of its class in ~1,365 binaries; array is 64 entries
   (proved by `_parseHevcSps`'s hard-coded `#0x40`), guard is `idx <= max` (missing lower bound),
   table read is `this + 0xc08 + 8*idx` and **returned**.
   *Missing:* whether the source byte can exceed 63 / go negative, and whether the returned
   pointer is dereferenced usefully.
   *Experiment:* resolve `CAVDDecoder +0x1624` (one trace), or a crafted MV-HEVC bitstream.

**None of the three is a primitive today**, and after §3.3 all three are *more* doubtful than
they looked at the start of the round, not less: #1's reachability is now in question on the
only app-openable producer, #2 is an untested hypothesis, #3 is a daemon-side defect whose
trigger is unproven. #2 is the best remaining *static* investment because it is cheap to kill or
confirm; #1's next step is a bounded trace, not a device run.

## 6. METHOD NOTES (two tool bugs found and fixed — both are this repo's own lessons)

1. **Halfword loads scale their immediate by 2.** I re-derived a `+0x34` reader scan in-line and
   compared the raw `imm12` against `0x34` instead of `imm12 * 2`. It returned a confident
   **zero hits** for a site I had just disassembled by hand. `d34read.py` already had this
   right (`((w >> 10) & 0xFFF) * 2 != FOFF`); the correct move was to reuse the proven tool
   rather than rewrite it. *Never trust an empty result* — again.
2. **`bti c; pacibsp` is one function entry, not two.** A "find the next `pacibsp`" end-detector
   truncates any arm64e function that starts with `bti c` to 4 bytes (it matched the `pacibsp`
   at `+4`). Cost: one wasted dump claiming `len=4 bytes`.

## 7. ARTIFACTS

| file | purpose |
|---|---|
| `analysis/priv24A435/kcoll.py` | whole-collection Mach-O harness (`iter_kexts`, `load`, VA↔offset, sections) |
| `analysis/priv24A435/sxguard.py` | sign-extend → signed-compare sweep; `--dir` walks an extracted cache; `--control` self-check |
| `analysis/priv24A435/d34read.py` | **every** halfword read at `+0x34` collection-wide + test-then-call classification |
| `analysis/priv24A435/fndump.py` | enclosing-function dump for a VA |
| `analysis/priv24A435/tri.py`, `xr.py`, `prodx.py`, `findimm.py` | window disasm / callers / producer tracing / immediate sites |
| `/tmp/ds24/dy` | the **1056-image** carve (volatile; regenerate with the `ipsw dyld extract` line above) |

## 8. HONEST CEILING

The campaign's own `REPORT_27_0_CVE_HUNT.md` says *"no app-reachable memory-corruption
vulnerability was proven in 24A435."* **This round does not overturn that**, and it would be
dishonest to present three "paths to kernel r/w" when what exists is one proven consumer plus
two unresolved hypotheses. What is new and defensible:

1. the sweep corpus grew 9 → 1056 images, and the sign-extended-index class is closed across it;
2. the `_dmaReferences` consumer **exists** (previous note said it did not) — so the counter is a
   real gate and the wrap bypasses a real check;
3. the `_dmaReferences` non-atomic reset is **defused** (previous note ranked it as the stronger
   candidate) — with fall-through-only evidence;
4. the class population is characterised well enough to say *why* the AVD hit is alone.
