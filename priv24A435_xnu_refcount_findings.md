# PRIV-24A435 LINE C — xnu `_dmaReferences` overflow: the fix has a signedness hole

> **CORRECTIONS + CONTINUATION — see `priv24A435_xnu_reachability.md` (same directory).**
> The reachability pass corrected three claims below and finished the producer map:
> 1. the check is in **`IOMemoryDescriptor.cpp`**, not `IODMACommand.cpp` (string-block
>    ordering; the function is `IOMemoryDescriptor::dmaCommandOperation`, vtable slot 0x90,
>    PAC diversity 0xa8a7, in 4 vtables);
> 2. the pin op is **3**, not 2 — the dispatcher computes `w9 = (w1 - 0x01000000) >> 24 = op-1`,
>    and the refcount path is reached only at `w9 == 2`, i.e. `w1 = 0x03000001` (pin) /
>    `0x03000000` (unpin);
> 3. the increment has **exactly one producer in the whole collection**:
>    `IODMACommand::setMemoryDescriptor` (slot 0x88, diversity 0xb91) at
>    `0xfffffff00b337ad8` — called from 120 sites in 37 kexts.
> The reachability chain from `AppleJPEGDriverUserClient::externalMethod` down to the
> increment is in the continuation file. Everything below about the *shape* of the hole
> (post-increment, signed compare, wrap to zero) is confirmed and stands.

Target: `/Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.kernel` (iOS 27.0 GM 24A435,
iPhone17,5). `__TEXT_EXEC` va `0xfffffff00ab60000` ↔ file off `0x230000`; strings live in
`__TEXT` (va `0xfffffff00700c000`, file off 0).

**HEADLINE: the overflow check Apple added in GM is a signed compare on a 16-bit counter —
it only covers `0x4000..0x7fff`. Past `0x8000` the counter sign-extends negative, the check
silently passes, the operation proceeds normally, and the counter walks on to `0xffff → 0`
— a wrap-to-zero while DMA references are outstanding. The class the fix was meant to close
(premature free while DMA in flight) remains reachable through the hole.**

## 1. The strings and their provenance

| string | file off | VA | b2 (24A5370h) | GM (24A435) |
|---|---|---|---|---|
| `_dmaReferences overflow @%s:%d` | 0xb5ead | `0xfffffff0070c1ead` | **absent** | present |
| `_dmaReferences underflow @%s:%d` | 0xb5ecc | `0xfffffff0070c1ecc` | present | present |

So the underflow guard predates the cycle; **the overflow check is the GM addition** —
Apple found that the counter could grow unboundedly. String neighbours place it in
`IODMACommand.cpp` (`IODMACommand` 0x…c1a6b, `dmaCommandOperation` 0x…c1ad9/0x…c1af4,
`IOGMD: not wired for the IODMACommand` 0x…c1eec, `complete() while dma active` 0x…c1f8c).

## 2. The check site — `dmaCommandOperation` @ `0xfffffff00b3454d4`

The function is an operation dispatcher: `w0`=IODMACommand, `w1` = op|arg packed
(`op = w1>>24`, `arg = w1 & 0xffffff`), `x2` = op descriptor, `w3` = descriptor size.
Ops seen: 0,1,2,3,4,5. **Op 2 with arg≠0 = pin a DMA reference; arg==0 = unpin.**

The increment path (op2, arg≠0), `0xfffffff00b34552c`:

```asm
cbz  w21, ->decrement                    ; arg==0 -> unpin
add  x8, x0, #0x34                       ; &cmd->_dmaReferences   (int16!)
mov  w9, #1
ldaddh w9, w8, [x8]                      ; ATOMIC ++  -> w8 = OLD value (zero-extended u16)
cbz  w8, ->first-pin (str xzr,[x0+0x38]) ; old==0: clear the +0x38 marker
sxth w8, w8                              ; sign-extend the 16-bit count
cmp  w8, #0x4000                         ; SIGNED compare vs 16384
b.lt ->work path (0xb34575c)             ; old < +16384 -> proceed to real work
adrp/add -> '_dmaReferences overflow @%s:%d'   ; log line 0xddd
bl   logger
; fall-through -> w9 still ==2, matches nothing -> default return 0xb345d78
; i.e. LOG + EARLY RETURN — but the ldaddh ALREADY STOOD.
```

The decrement path (op2, arg==0), `0xfffffff00b345740`:
```asm
ldrh   w8, [x0+0x34]     ; UNSIGNED read
cbz    w8, ->underflow log (0xb345dc4, '_dmaReferences underflow @%s:%d', line 0xde3)
ldaddh -1                ; atomic --
```

The work tail (`0xb34575c`, reached when the count check passes) requires `w3 >= 0x40`,
then processes the descriptor: `[x0+0x90]` = the memory descriptor, `[x0+0x20]` flag
bits (`tbnz #0x12`, `tbnz #0xc`), `[x2]` descriptor fields, `[x0+0x38]` marker,
a per-segment walk, and fields like `[x2+0x10]` / `[x2+0x24]` written back into
`desc+0x28` (`stp x23, x9, [x2,#0x28]` near the tail).

## 3. THE HOLE — three compounding facts

1. **Post-increment check.** `ldaddh` executes unconditionally; the test runs on the OLD
   value *after* the store. Every call — including ones that "fail" the bound — leaves
   `_dmaReferences` +1. The bound skips the pin *work* but cannot un-bump the counter.
   → the count can run ahead of real pins (drift up).
2. **Signed compare on a 16-bit field.** `sxth` + signed `b.lt #0x4000` means values
   `0x8000..0xffff` (negative when sign-extended) **pass** the test. So the detector is
   only live in `[0x4000, 0x7fff]`. At `0x8000` the op stops logging AND resumes the real
   work path — pins continue accumulating while the counter is a *negative* int16.
3. **Wrap to zero.** From `0x8000` the counter proceeds `0x8001 … 0xffff → 0x0000` with
   every subsequent pin. `_dmaReferences == 0` is the object's "no DMA active" state
   (decrement path treats 0 as underflow; increment-from-0 clears `+0x38`). Reaching 0
   while pins are outstanding makes any `== 0 -> safe to teardown` logic fire mid-DMA —
   the refcount-to-free/UAF shape the fix targeted.

**Cost to reach the hole:** `0x8000` = 32,768 pin ops on ONE IODMACommand — small for an
app-driven loop *if* a driver path lets a userspace request drive repeated pin operations
without matching completes (e.g., per-segment/per-prepare pinning reachable through
IOKit UC calls; the campaign has proven app→driver DMA paths in IOSurface/IOGPU/AVD).
The overflow log will fire 16,384 times — noisy but log-only; past `0x8000` it goes quiet.

Also note the decrement reads the field **unsigned** (`ldrh`): a negative (wrapped)
count is "nonzero", so unpins keep decrementing — each unpin of a real pin drives the
already-low count further toward/past zero. The two directions compound.

## 4. Reachability — the open question

`dmaCommandOperation` has no `bl`/`b` callers in `__TEXT_EXEC` (raw-encoding scan, all
sites) — it is entered indirectly (vtable/op dispatch inside IODMACommand). The next
step is the caller chain: which IODMACommand method emits op2-pin, and which driver UC
operations turn into pin calls (candidates: `IODMACommand::prepare/prepareWithAddress/
prepareForDMA`-style paths called by IOSurface/USB/AVD-family drivers on app-supplied
descriptors). If any app-influenceable driver can pin repeatedly on one command, the
counter is drivable to the wrap.

## 5. Sibling hunt — the systematic follow-on (planned, not yet run)

The fix pattern to sweep for: LSE `ldadd*`/`swp*`/`cas*` counter updates in `__TEXT_EXEC`
lacking a subsequent bound test. `ldaddh` at the check site encodes as `0x78290108`
(bits[31:24]&0x3f == 0x38 for the ldadd family + bit21 set + opc[14:12]==000 for ADD).
Scanner: `analysis/priv24A435/` raw-encoding pass over the 9MB text — each hit then
checked for a bound on the result register within ~8 instructions. The same producer
rule from PRIV_HUNT §2E applies: the bound may live in the caller.

## 6. Verdict and report shape

- **GM's overflow check is defective-by-design**: signed compare + post-increment →
  the wrap-to-zero remains reachable (needs ~64K ops on one object). Severity depends
  entirely on whether the pin path is app-drivable — to be settled by the caller-chain
  trace (§4). If reachable: `_dmaReferences` 0-wrap → object tears down DMA state while
  hardware still maps/writes = a kernel-write-shaped UAF.
- **Reportable regardless of reachability**: as a hardening note — "the new
  `_dmaReferences overflow` check in IODMACommand.cpp is a signed compare on a 16-bit
  counter and is executed after the atomic increment; values ≥0x8000 bypass it, and the
  counter can still wrap to zero."
- The underflow check (b2-era) has the mirror-image weakness (unsigned `ldrh` gate) but
  is secondary: underflow needs count==0 while decrementing, which the wrap itself can
  manufacture.

*Artifacts: `analysis/priv24A435/xnu_harness.py`, `analysis/priv24A435/rawref.py`
(desync-proof adrp/add + bl/b scanners — required for the 9MB text). The prior stub
`priv24A435_xnu_refcount.md` (Status: STARTED, from the dead round-1 agent) is left
untouched; this file supersedes it.*
