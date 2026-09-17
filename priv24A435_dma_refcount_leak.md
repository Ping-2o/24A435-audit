# PRIV-24A435 LINE C — `_dmaReferences`: one increment path has no matching decrement

Target: iOS 27.0 GM **24A435** (iPhone17,5), `com.apple.kernel` carve.
Supersedes one specific claim in `priv24A435_xnu_reachability.md` (§6.4) — see §4 below.

Reproduce: `python3 analysis/priv24A435/dma_refbalance.py`

---

## 0. HEADLINE

`priv24A435_xnu_reachability.md` §6.4 states: *"Both branches have a matching decrement
(op-3 arg 0 for the checked branch; op-6 → release helper for the unchecked one)."*

**That is wrong for the `op-1` (map) path.** The map worker at `0xfffffff00b345fec`
acquires a reference through the **unchecked** RETAIN helper at `0xfffffff00b34612c`
**without any test on `desc+0x98`**, while the only release for that path —
implementation A's `op-6` handler at `0xfffffff00b34572c` — is gated on
**exactly `desc+0x98 != 0`**:

```
impl A, op 6  (0xfffffff00b345708)                    <-- the ONLY release on this path
  0xfffffff00b345710  cmp   w3, #0x58      ; descriptor size must be >= 0x58
  0xfffffff00b345714  b.lo  #0xfffffff00b345d78
  0xfffffff00b345718  ldr   w8, [x0, #0x98]
  0xfffffff00b34571c  cbz   w8, #0xfffffff00b345d78   ; *** [x0+0x98]==0  -> RELEASE SKIPPED ***
  0xfffffff00b34572c  bl    #0xfffffff00b340a44       ; RELEASE helper

map worker 0xfffffff00b345fec, entry 0xb3460b4        <-- the acquire
  0xfffffff00b346114  blraa x10, x16                  ; virtual map (div 0x2b52)
  0xfffffff00b346118  cbnz  w0, #0xfffffff00b346134   ; only failure skips the retain
  0xfffffff00b34612c  bl    #0xfffffff00b3409a4       ; RETAIN, UNCHECKED, no +0x98 test
```

Between `0xfffffff00b3460b4` and `0xfffffff00b34612c` there is **no read of `[x0+0x98]`**.
The `+0x98` test exists on the *other* entrance to the same function (the fast path at
`0xfffffff00b34603c`/`0xfffffff00b346044`, which bails to `0xfffffff00b346130`), and it
exists on `op 6`. It was simply omitted on the one branch that retains.

Consequence: a map that takes the `0xb3460b4` entrance while `desc+0x98 == 0` acquires a
reference through a helper with **no bound at all** (the same helper
`priv24A435_xnu_refcount_findings.md` §3 identifies), and `op 6` will skip the matching
release because of the `+0x98` test. **+1 permanent drift per such call.** That is the
"unbalanced increment" §6.4 says was not found.

---

## 1. The mutation census (`dma_refbalance.py`)

Raw-encoding scan of the 9 MB `__TEXT_EXEC`. The script refuses to report unless all
seven hand-verified control sites decode as expected — an earlier revision silently
scanned the blob at word instead of byte offsets and returned "0 call sites", which is
exactly the failure mode this project's own notes warn about ("never trust an empty
result").

```
CONTROL  7/7 hand-verified sites decode as expected

[1] INLINE  add rD,rN,#0x34 + LSE atomic on rD
    0xfffffff00b3409dc  ldaddh  (inside RETAIN helper 0xb3409a4)     <-- unchecked ++
    0xfffffff00b340a80  ldaddh  (inside RELEASE helper 0xb340a44)    <-- --
    0xfffffff00b345538  ldaddh  (impl A op 3, arg!=0)                <-- CHECKED ++
    0xfffffff00b345750  ldaddh  (impl A op 3, arg==0)                <-- CHECKED --
    halfword (this field) : 4      other width @#0x34 : 31 (not this field)

[2] OUTLINED  bl to the shared refcount helpers
    RETAIN  0xfffffff00b3409a4   sites = 4
        0xfffffff00b340818   in 0xfffffff00b340688   (impl B op 5)
        0xfffffff00b34593c   in 0xfffffff00b3450c8   (impl A work path)
        0xfffffff00b34612c   in 0xfffffff00b345fec   (map worker, entry 0xb3460b4)  <-- NO +0x98 GUARD
        0xfffffff00b346208   in 0xfffffff00b345fec   (map worker, fast path — DOES test +0x98)
    RELEASE 0xfffffff00b340a44   sites = 3
        0xfffffff00b340710   in 0xfffffff00b340688   (impl B op 6)
        0xfffffff00b343c04   in 0xfffffff00b341718
        0xfffffff00b34572c   in 0xfffffff00b3450c8   (impl A op 6)                 <-- +0x98 GATED

[2b] adrp+add materialisations of either helper address: none
     -> both helpers are reached only by direct `bl`; no indirect dispatch to miss
```

Important correction to the raw counts: the two RETAIN sites inside `0xfffffff00b345fec`
are **mutually exclusive branches**, not two acquires — the function retains at most once
per call. So "4 retain sites / 3 release sites" does **not** by itself imply a leak; the
leak is the *guard* asymmetry in §0, not the site count.

**Non-atomic write, worth carrying separately:** `0xfffffff00b346888  strh w31, [x19, #0x34]`
— a plain (non-atomic) zeroing store to the field, in a function that also participates in
the refcount path. A refcount reset that is not an atomic is its own defect class; not
analysed here.

---

## 2. What the map worker is, and the three ways into the unguarded branch

`0xfffffff00b345fec` is the worker called from implementation A's work path
(`0xfffffff00b3458d8`, `0xfffffff00b345a04` — i.e. from `op 1` and from `op 3` after the
refcount test passes). Its job: make one virtual call into the descriptor's
`vtable+0x550` (PAC diversity `0x2b52`), and on success take one reference via the
RETAIN helper.

Entrance to the **unguarded** branch (`0xfffffff00b3460b4`):

```
0xfffffff00b346020  cbnz  x5, #0xfffffff00b3460b4   ; (a) the caller passed x5 != 0
0xfffffff00b346024  and   w9, w9, #0xf0
0xfffffff00b346028  cmp   w9, #0x20
0xfffffff00b34602c  b.eq  #0xfffffff00b3460b4       ; (b) (desc[0x20] & 0xf0) == 0x20
0xfffffff00b346030  ldr   x9, [x0, #0x50]
0xfffffff00b346034  cmp   x6, x9
0xfffffff00b346038  b.ne  #0xfffffff00b3460b4       ; (c) x6 != desc[0x50]  (dev-addr mismatch)
```

Condition (c) — **the device address supplied differs from the one recorded on the
descriptor** — is an ordinary runtime event (a re-map at a new DMA address), not an
error path. That is why this matters: the unguarded branch is not exotic.

The guarded entrance is the fast path, whose tests are visible in the same listing:

```
0xfffffff00b34603c  ldr   x9, [x0, #0x90]
0xfffffff00b346040  cbz   x9, #0xfffffff00b346130   ; desc[0x90] == 0 -> return success, NO retain
0xfffffff00b346044  ldr   w8, [x0, #0x98]
0xfffffff00b346048  cbz   w8, #0xfffffff00b346130   ; desc[0x98] == 0 -> return success, NO retain
```

Both entrances can return `0` (success). Only one of them is conditioned on `+0x98`.

---

## 3. Why this is the shape that grows a 16-bit counter

- The increment is on a helper with **no bound** (`0xb3409a4`, no `cmp #0x4000` anywhere —
  `priv24A435_xnu_refcount_findings.md` §3.2).
- The drift is **monotonic**: nothing decrements the extra reference, so it accumulates
  *across* calls. Reaching `0x4000` does **not** require 16,384 concurrent DVA mappings —
  only 16,384 calls that take the unguarded branch, which a loop can do.
- Past `0x4000` the signed compare (`sxth` + `b.lt #0x4000`) logs and falls through to the
  default return; past `0x8000` the field sign-extends negative and the check is silently
  satisfied. This is the hole described in the findings note, now with a way to *drive* it.

This does not by itself produce an out-of-bounds access — §6 of the reachability note still
stands: no consumer was found that treats `== 0` as "no DMA in flight". **This is a
counter-integrity defect with a demonstrated driver, not a memory-safety primitive.** The
value of the finding is that it removes the "needs 32,768 simultaneous harmless references"
objection that made the line look empirically dead.

---

## 4. Status

**Proven, byte-exact:**
1. The `+0x34` mutation census is complete for the kernel: 4 halfword atomic sites
   (2 inline in impl A, 2 inside the helpers), 4 RETAIN call sites, 3 RELEASE call sites,
   no indirect dispatch to the helpers, 1 non-atomic zeroing store. Reproducible with a
   control block that refuses to report on desync.
2. `op 6`'s release is gated on `desc+0x98 != 0` (`0xfffffff00b34571c`).
3. The RETAIN at `0xfffffff00b34612c` is reached from `0xfffffff00b3460b4` with **no read
   of `[x0+0x98]`** in between.
4. `0xfffffff00b34612c` is one of the four `bl` sites of the unbounded helper
   `0xfffffff00b3409a4`.
5. **§6.4 of `priv24A435_xnu_reachability.md` is refuted**: the unchecked branch does not
   have a matching decrement when the acquire takes the `0xb3460b4` entrance.

**Not proven:**
1. That a caller can reach `0xfffffff00b3460b4` with `desc+0x98 == 0`. The `+0x98` test is
   absent on the acquire side, but the *caller* may establish the invariant
   (`[[0xfffffff00b345fec]]`'s callers, and `IODMACommand::setMemoryDescriptor`'s
   `x5`/`x6` arguments, decide this). This is the next step and it is a bounded one: walk
   the two call sites `0xfffffff00b3458d8` / `0xfffffff00b345a04` and the argument
   provenance of `x5`/`x6`. **If the caller enforces `desc+0x98 != 0` before mapping, this
   collapses to a defence-in-depth gap, exactly as the four previous candidates did.**
2. That any of this is reachable from an app-facing userclient selector. The static chain
   in `priv24A435_xnu_reachability.md` §1 ends at `IODMACommand::setMemoryDescriptor`
   (120 sites / 37 kexts); that is where the app-facing selectors attach, but the specific
   `op-1` map calls with the required argument combination have not been identified.
3. That the counter can actually be driven to `0x4000`. Static only.

**Reportable now** (hardening, vendor-facing): the invariant "a reference is only taken
when `desc+0x98 != 0`" is enforced on the descriptor's fast path and on the release, but
not on the map worker's `0xb3460b4` entrance, which takes the reference through the
out-of-line retain helper that carries no bound on the counter at all. Recommend the
`+0x98` test be applied on every acquire, and an unsigned post-increment bound on every
increment path.

---

## 5. Next step, in order

0. **Take §6.3 first.** The non-atomic `strh wzr, [x19, #0x34]` at `0xfffffff00b346888` is a
   cheaper path to `== 0` than the drift, and it is the same one question: is the reset
   reached only on a fresh prepare? Establish the entry conditions of the function at
   `0xfffffff00b346638` — one question, one report file.
1. **Walk `x5`/`x6` at the two map-worker call sites** (`0xfffffff00b3458d8`,
   `0xfffffff00b345a04`) back through impl A's work path, and determine whether
   `desc+0x98 == 0` is reachable while any of §2(a)/(b)/(c) holds.
2. Only if (1) is positive: identify an app-facing selector whose UC call lands in
   `IODMACommand::setMemoryDescriptor` with that argument combination, using the
   per-kext closures already in `reach/batch_chain_out.txt`.
3. Only then: a runtime reproducer. Note the counter is per-`IOMemoryDescriptor`, so the
   observable is the `_dmaReferences overflow @%s:%d` kernel log line
   (`priv24A435_xnu_reachability.md` §5.1 — airlift is a file primitive and cannot read
   kernel logs directly, but can lift files out of `/var/mobile/Library/Logs`).

---

## 6. Two corrections forced by the follow-up checks

> **Status update (round 3):** §6.1's point stands (string ordering settles nothing), and §6.2's
> class-ownership question is still open. §6.3 is now **defused** — see the note at §6.3 and
> `priv24A435_kernel_rw_round3.md` §3.2. The surviving defect on this line is the
> signed-compare + post-increment shape (§3 above), whose reachability is a runtime question:
> 65,536 prepares on one `IODMACommand`. The consumer that makes it worth pursuing is proven in
> `priv24A435_dmaref_consumer.md`.

### 6.1 The "string neighbour" argument in both notes is invalid

`priv24A435_xnu_refcount_findings.md` §1 places the check by string proximity:
*"String neighbours place it in `IODMACommand.cpp` (`IODMACommand` 0x…c1a6b,
`dmaCommandOperation` 0x…c1ad9/0x…c1af4, `IOGMD: not wired for the IODMACommand` 0x…c1eec)"*,
and `priv24A435_xnu_reachability.md` overrides that to `IOMemoryDescriptor.cpp` using the same
method. **Both compared addresses that are not neighbours.**

The overflow string really is at VA `0xfffffff0070c1ead`. In `__TEXT` (va `0xfffffff00700c000`
↔ file offset 0) that is file offset **`0xb5ead`** — the findings note even records the file
offset correctly — but the `IODMACommand` / `IOMemoryDescriptor` / `IOGMD` addresses quoted
against it (`0x…c1a6b`, `0x…c1cc0`, `0x…c1eec`) are at file offsets `0x15a6b` / `0x15cc0` /
`0x15eec`. Those are **`0xa0000` bytes away**, in the `__FILE__`-path block, not adjacent.

The verified neighbourhood (file offset `0xb5e00..0xb6000`) is:

```
  entryOffset @%s:%d
  map enter err %x @%s:%d
  site.IOVirtualRange
  bad dir for upl 0x%x @%s:%d
  short external upl @%s:%d
  IOMemoryDescriptorSharingContext
  _dmaReferences overflow @%s:%d          <-- target
  _dmaReferences underflow @%s:%d
  IOGMD: not wired for the IODMACommand @%s:%d
  !pageList phys_addr @%s:%d
  fMapped %p %s %qx @%s:%d
  IOMemoryDescriptor 0x%zx prepared read only
  memRefEntry @%s:%d
  complete() while dma active @%s:%d
  IOMemoryDescriptor::makeMapping !64bit @%s:%d
```

That block is **mixed**: `IOMemoryDescriptorSharingContext`, `IOMemoryDescriptor 0x%zx prepared
read only`, `makeMapping`, `memRefEntry`, `IOVirtualRange` are the `IOMemoryDescriptor` plane,
while `fMapped`, `complete() while dma active` and `IOGMD: not wired for the IODMACommand` are
the `IODMACommand` plane. So string ordering does **not** settle ownership, in either direction.
**The class-ownership claim in both notes is unsupported by the artifact it cites.**

### 6.2 Ownership, from object layout instead

The object carrying the `+0x34` halfword is the same object impl A's `op 2` query reports to the
caller on one line (`0xfffffff00b345648`):

```
  x2[0x00] = x0[0x50]      ; the DMA/device address
  x2[0x08] = x0[0x68]      ; the prepare count (the field 0xfffffff00b33732c increments)
  x2[0x0c] = x0[0x98]      ; the field op 6's release is gated on
```

and it also carries `+0x20` (flag word: bits 0xc, 0x12, 0x14, 0x8000), `+0x34`, `+0x88`, `+0x90`,
`+0x9c`, `+0xa0`, `+0xa8`. The `+0x68` prepare count is decision-relevant: it is written by
`0xfffffff00b33732c` (`ldp w19, w9, [x0, #0x64]; add w10, w9, #1; str w10, [x0, #0x68]`) — the
function the notes call `IODMACommand::dmaCommandOperation`. If `+0x34` lives on that same object,
then the counter is **per-IODMACommand, not per-IOMemoryDescriptor**, and the "32,768 outstanding
references on one descriptor" framing in the findings note (§3, §6.3) is aimed at the wrong
object. **Not proven** — it needs one pass confirming the receiver of `0xfffffff00b3454d4` and the
receiver of `0xfffffff00b33732c` are the same class. Flagged because it changes what "driving the
counter" means.

### 6.3 A second candidate: the counter is reset with a non-atomic store

> **CORRECTION (round 3): this candidate is DEFUSED — see
> `priv24A435_kernel_rw_round3.md` §3.2.** The store at `0xfffffff00b346888` is reachable only
> by fall-through (a raw-encoding scan of all `__TEXT_EXEC` finds **zero** `b`/`b.cond` sites
> targeting it), and both entrances are pre-teardown: the first-prepare entrance raises the
> `+0x8c` bit0 flag with nothing mapped, and the re-prepare entrance releases the old memory
> descriptor at `+0x60` (`0xfffffff00b346774`) before reaching the common tail. No path zeroes
> the counter with a previous prepare's mapping still outstanding. The text below is kept for
> the record; the "stronger, cheaper candidate" ranking it ends with is withdrawn.

The `strh` hit reported by the census at `0xfffffff00b346888` is inside the DMA map/prepare core
(function starts `0xfffffff00b346638`), in a state-reset sequence:

```
0xfffffff00b34687c  and  w20, w27, #0xffff7fff
0xfffffff00b346880  str  w20, [x19, #0x20]     ; flags
0xfffffff00b346884  str  x4,  [x19, #0x70]
0xfffffff00b346888  strh wzr, [x19, #0x34]     ; *** _dmaReferences := 0, NON-ATOMIC ***
0xfffffff00b34688c  str  xzr, [x19, #0xa0]
0xfffffff00b346890  str  wzr, [x19, #0x9c]
```

If this reset can run while references are outstanding, it reaches `_dmaReferences == 0` with
live references **directly** — no 32,768-call climb, which is the empirical obstacle that made
this line look dead. Whether it can is exactly the same question as §4(1): is the reset reached
only on a fresh prepare (where the invariant holds by construction), or on a re-prepare?
The same function loads `+0x98` at `0xfffffff00b346998` and stores it at `0xfffffff00b3469a4`
(`ldr w9,[x19,#0x98]; sub w9, w9, w24; add w8, w9, w8, lsr #14; str w8, [x19,#0x98]`), i.e. it
maintains `+0x98` as a *counter*, not a flag — which makes the `cbz` gates in impl A (`op 6`) and
the map worker (fast path) read as "is anything mapped", and makes the unguarded retain in §0
more suspicious, not less. This is a stronger, cheaper candidate than the drift and should be
taken first.

---

*Artifacts: `analysis/priv24A435/dma_refbalance.py` (census + control block),
`analysis/priv24A435/reach/gdump.py` (window disassembly), kernel carve at
`/Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.kernel`. Method note: raw word-indexed
scanning must convert the word index to a **byte** offset — the first revision of this
script got that wrong and produced a confident, entirely empty result; the control block
now catches it.*
