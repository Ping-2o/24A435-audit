# PRIV-24A435 — THE `_dmaReferences` CONSUMER EXISTS. LINE C is a UAF precondition, not just a hardening gap.

Target: iOS 27.0 GM **24A435**, `/Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.kernel`.
Reproduce: `prodx.py` / `d34read.py` / `tri.py` / `rdstr.py` (see §6).

---

## 0. HEADLINE

Three of the campaign's own notes conclude, in these words, that this line is dead:

> *"**A consumer that treats `_dmaReferences == 0` as "no DMA in flight" and acts on it.** Not found."*
> — `priv24A435_xnu_reachability.md` §6.1
>
> *"Until (1) or (3) is answered, the honest severity is: **a kernel hardening defect** — an
> incomplete bound on a refcount — with no demonstrated memory-safety consequence."*
> — same file, §6

**That is refuted.** The consumer exists, it is exactly the described shape, and it is
the function that performs the completion:

```
function 0xfffffff00b341718            (IOMemoryDescriptor::complete, IOMemoryDescriptor.cpp)
  0xfffffff00b343bdc  ldrh  w8, [x0, #0x34]        ; w8 = _dmaReferences  (16-bit field)
  0xfffffff00b343be0  cbnz  w8, #0xfffffff00b343db0 ; if (refs != 0) -> ASSERT
  0xfffffff00b343be4  ...                            ; refs == 0 -> PROCEED with completion
  0xfffffff00b343c04  bl    #0xfffffff00b340a44     ; shared refcount helper, x2==0 path (see 3.5)

assert target 0xfffffff00b343db0:
  0xfffffff00b343db4  add   x8, x8, #0xdb9          ; "IOMemoryDescriptor.cpp"
  0xfffffff00b343db8  mov   w9, #0x14d3             ; line 5331
  0xfffffff00b343dc4  add   x0, x0, #0xf8c          ; "complete() while dma active @%s:%d"
  0xfffffff00b343dc8  bl    #0xfffffff00b41f6bc     ; noreturn log/panic wrapper
```

Read off the binary, not inferred:

```
$ python3 analysis/priv24A435/rdstr.py com.apple.kernel 0xfffffff0070c1f8c 0xfffffff0070c1db9
0xfffffff0070c1f8c: complete() while dma active @%s:%d
0xfffffff0070c1db9: IOMemoryDescriptor.cpp
```

`0xfffffff00b41f6bc` is a noreturn wrapper — it does `mov x6, x30; xpaci x6` (captures the
caller's return address) and tail-calls `0xfffffff00aba5090` on a 0x1c0-byte frame, and a
fresh function prologue begins immediately after the `bl`, which is only possible if the
call never returns. So the field is not merely logged: **`complete()` refuses (fatal) when
`_dmaReferences != 0`.**

## 1. WHY THIS CHANGES THE VERDICT

The counter is a **safety gate**, not a statistic. `complete()` runs only when it reads zero.
So any mechanism that produces `_dmaReferences == 0` **while DMA is genuinely outstanding**
turns the defect into exactly the class the iOS 27 fix (`_dmaReferences overflow`) appears to
target: **premature completion of a descriptor with DMA still in flight** — the
refcount-to-free/UAF shape.

Every mechanism needed for that is already documented in the campaign's own notes; only the
consumer was missing, and it is now found:

| mechanism | where | note |
|---|---|---|
| increment guard is a **signed** compare (`sxth` + `b.lt #0x4000`) → `>= 0x8000` bypasses it, 16-bit counter walks to 0 | `0xfffffff00b345540` | `priv24A435_xnu_refcount_findings.md` §3 |
| unbalanced increment: map worker retains via the **unchecked** helper (no `+0x98` test); release is gated on `+0x98 != 0` → permanent `+1` drift | `0xfffffff00b34612c` vs `0xfffffff00b34571c` | `priv24A435_dma_refcount_leak.md` §0 |
| **non-atomic reset** to 0 in the DMA state-reset sequence | `0xfffffff00b346888` | `priv24A435_xnu_reachability.md` §6.3 |

The reset is the direct route — it reaches `== 0` with no 65,536-call climb:

```
0xfffffff00b34687c  and  w20, w27, #0xffff7fff
0xfffffff00b346880  str  w20, [x19, #0x20]      ; flags
0xfffffff00b346884  str  x4,  [x19, #0x70]
0xfffffff00b346888  strh wzr, [x19, #0x34]      ; *** _dmaReferences := 0, NON-ATOMIC ***
0xfffffff00b34688c  str  xzr, [x19, #0xa0]
0xfffffff00b346890  str  wzr, [x19, #0x9c]
```

## 2. SEVERITY, STATED PRECISELY (both directions)

The direction matters, and the two directions have different severities:

* **drift up** (the unbalanced retain) → `complete()` sees non-zero → **fatal assert**
  (`complete() while dma active`) → kernel **panic / DoS**, not corruption;
* **wrap to 0, or the non-atomic reset** → `complete()` sees zero → **proceeds while DMA is
  in flight** → the **UAF**, and no assert fires.

So the interesting direction is the one that *bypasses* the guard, which is also the one the
signed-compare hole and the non-atomic reset both provide.

## 3. WHAT IS PROVEN / NOT PROVEN

**Proven, byte-exact:**
1. A 16-bit field at `+0x34` is **read** at `0xfffffff00b343bdc` in `0xfffffff00b341718`,
   tested with `cbnz`, and a non-zero value takes a **non-returning** assert path whose
   message is `complete() while dma active` at `IOMemoryDescriptor.cpp:5331`. The read has
   exactly one predecessor (`0xfffffff00b343b68`, a `cbz` inside the same function), and the
   function saves/restores its receiver (`mov x22, x0` / `mov x0, x22`) around its inner
   loop, so the receiver is the object being completed.
2. The assert string and file string resolve at the VAs the code loads — read directly from
   `__cstring`, not inferred from string neighbourhoods (the method error §6.1 of the
   reachability note warns about exactly that).
3. A **non-atomic** `strh wzr, [x19, #0x34]` reset exists in the DMA state-reset sequence.

**3.5 A correction to the campaign's helper model, found while verifying this.** The site
`0xfffffff00b343c04` is *not* a plain decrement: `0xfffffff00b340a44` is a larger function
that reads its own `[x19,#0x34]` behind a `cbz x2, 0xb340b28`, and the caller sets
`mov x2, #0` immediately before the call, so it takes the `x2 == 0` branch and **does not
touch the counter**. Separately, the census's RETAIN entry is sound: the increment really is
at `0xfffffff00b3409dc` (`add x8,x0,#0x34; mov w9,#1; ldaddh w9,w8,[x8]`) with **no bound**,
guarded only by a `cbz x2` at `0xfffffff00b3409d0`. Both facts are recorded because the
earlier notes describe `0xb340a44` as "the RELEASE helper (--)" without qualification.

**Not proven:**
1. That `complete()` can be reached concurrently with in-flight DMA **for the same
   descriptor** — i.e. the entry conditions of the reset function (`0xfffffff00b346638`): is
   it reached only on a fresh prepare, or on a re-prepare with references outstanding? This is
   the single deciding question and it is bounded (the campaign's §5 step 0).
2. That the increment path is app-drivable to the wrap (unchanged from before: static only).
3. That `0xfffffff00b343bdc` is reached for *every* descriptor, rather than only for a
   subclass; the function is large and the block is reached by branch.

## 4. METHOD NOTE — WHY THIS WAS MISSED, AND THE FIX

The campaign swept the field for **atomics** (`field_sweep.py`) and for the two log strings,
and concluded "nothing frees, tears down, or short-circuits on the value". The read is a
plain `ldrh`, not an atomic, so it was invisible to an atomic census. The reachability note
itself names the remedy — *"would be found by sweeping for **reads** of `descriptor+0x34`
rather than atomics"* — and that sweep was, as far as the notes record, never run.

`d34read.py` runs it: 451 halfword reads at `+0x34` collection-wide, of which 10 have the
"test the value, then call" shape a consumer has. The kernel ones:

| site | function | shape |
|---|---|---|
| `0xfffffff00b343bdc` | `0xfffffff00b341718` | `cbnz` → assert `complete() while dma active` **← the consumer** |
| `0xfffffff00b1a5b40` | `0xfffffff00b1a5408` | `cbnz` → skip |
| `0xfffffff00b414a00` | `0xfffffff00b414180` | `cbz` → skip (opposite sense) |
| `0xfffffff00b420bc0` | `0xfffffff00b4207bc` | table-indexed (`umaddl`, stride 0xc0), `cmp` |

The other three are different objects or read-only queries; only `0xfffffff00b343bdc` is on a
completion path and gated by the same field width.

## 5. WHAT TO DO WITH IT

1. **Reportable to Apple now, at higher severity than the hardening note**: the completion
   guard exists and reads a 16-bit counter whose increments are (a) unbounded on one branch,
   (b) signed-compared on the other, and (c) resettable by a **non-atomic** store. The
   consumer makes the counter safety-relevant; the defects make it forgeable.
2. **The one deciding experiment** remains the campaign's §5 step 0: entry conditions of
   `0xfffffff00b346638`. If the reset is only on a fresh prepare, this collapses to a
   hardening note (but a much stronger one than filed — the guard is now known to exist and
   to be defeatable). If a re-prepare can hit it, it is a UAF.
3. Do **not** file this as a demonstrated UAF yet — the concurrency condition (§3.1) is
   unproven, and this project's notes are right that an over-claimed UAF damages the parts
   that are solid.

## 6. REPRODUCE

```
# the consumer
python3 analysis/priv24A435/tri.py com.apple.kernel 0xfffffff00b343bdc 0x50 0x50
# the strings the assert loads
python3 analysis/priv24A435/rdstr.py com.apple.kernel 0xfffffff0070c1f8c 0xfffffff0070c1db9
# the non-atomic reset
python3 analysis/priv24A435/tri.py com.apple.kernel 0xfffffff00b346888 0x30 0x30
# the collection-wide read sweep that found it
python3 analysis/priv24A435/d34read.py
```
