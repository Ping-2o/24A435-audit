# PRIV-24A435 — round 2: the request lifecycle, the client-controlled teardown gate, and two refuted leads

Continuation of `priv24A435_reach_full_chain.md`. That document closed the descriptor-class
question (§0–§14) and left three leads: the `_dmaReferences` wrap (§9), a double release of the
client's `IOSurface` via a double `finish_io_gated` (§12), and the "alias the caller's struct"
candidate `C3` from `../jpeg_iostruct.md`.

This pass was asked to **find a full LPE on 27.0 GM (24A435)** with a *new* method — no build
diffing. It rebuilt the driver's object lifecycle from scratch, and it **refutes §12's lead and
C3's framing**, while finding a real, client-controlled defect of a different kind.

> **Bottom line: no full LPE is demonstrated, and this pass narrows rather than widens the
> candidate set.** Two of the three remaining leads are now closed as *unreachable by
> construction*, one new client-controlled defect is proven (a kernel heap leak + a
> client-forced premature DMA teardown), and the one lead that survives is restated with a
> sharper bar.

---

## 0. Method — what is new here, and why it is stronger than the earlier passes

The earlier passes drove the analysis from a known call chain and then tried to reach a
consequence. This pass instead **reconstructed the driver's object model first**, which turned out
to be the cheapest way to answer "can X happen twice?".

Three facts made that possible, and all three are reusable:

1. **The extracted kext carries `LC_FUNCTION_STARTS`.** `com.apple.driver.AppleJPEGDriver` has
   `LC_FUNCTION_STARTS` with `datasize = 0x848` → **1807 exact function starts**. No more
   prologue-guessing (`fn_bounds` is a `bisect`). This is what the earlier passes approximated with
   "nearest preceding `btab`", which the prior document itself records as having produced two false
   leads (§19.6).

2. **The extracted kext carries no local fixup information.** It has `LC_SYMTAB` (with `nsyms = 0`
   — stripped), `LC_DYSYMTAB`, `LC_UUID`, `LC_SOURCE_VERSION`, `LC_FUNCTION_STARTS` — and **no
   `LC_DYLD_CHAINED_FIXUPS` and no `LC_DYLD_INFO`**. The pointer words in `__DATA_CONST` / `__DATA`
   are still in *kernelcache* chained form, so they decode directly with the kernelcache bias
   (`PTR_BIAS32 = 0x7004000`, `HIGH32 = 0xFFFFFFF000000000`). Calibration: the slot
   `0xfffffff00807c5a0` decodes to `0xfffffff00a35b584`, matching the prior document's §1.

   **Gotcha that cost a round:** the extracted kext's *section* file offsets are not consistent with
   its *segment* file offsets — for `__DATA_CONST` they differ by `0xC0`
   (`__kalloc_type` is at section offset `0x4CEC0` but at segment-derived offset `0x4CF80`). The
   **segment** mapping is the correct one (verified: file `0x4CF90` holds the encoded pointer to the
   string `site.AppleJPEGWrapperControlV14`). Any scan that uses the section `offset` field for
   `__DATA_CONST` silently reads the wrong bytes.

3. **`__kalloc_type` is a site→object map.** Each entry is `0x40` bytes with the site string pointer
   at `+0x10`, the type name at `+0x20`, a flags word at `+0x28` and **the object size at `+0x2C`**.
   Matching those descriptors against the `adrp+add` sites that materialise their addresses gives
   every allocation and free of a typed object, with no symbols at all. This is the technique that
   produced the lifecycle in §1.

**Note on the `+0x2C` size field.** For `site.JpegRequest` all 14 views report `0x558`, which
cross-checks against the code: `finish_io_gated` reads `[req+0x54c]` and `[req+0x550]`, so the
object is at least `0x554` bytes. (`+0x28 = 0x64` is *not* the size — it is the flags word that
`kalloc_type`/`kfree_type` test for bits `0x8000`, `0x10` and `8`.)

---

## 1. The `JpegRequest` object — full lifecycle (PROVEN)

**Stubs.** Two `__auth_stub`s carry the typed allocator:

| stub | target | role |
|---|---|---|
| `0x903c588` | `0xfffffff00b2d0948` → `0xfffffff00abe7ef4` | **`kalloc_type`** (reads `[desc+0x2c]` as the size, `[desc+0x28]` as flags → zalloc flags `4`/`0x8004`) |
| `0x903c538` | `0xfffffff00b2d0b44` → `0xfffffff00abe8414` → `0xfffffff00abe7fb0` | **`kfree_type`** (`(desc, ptr, size)`; `size = [desc+0x2c] & 0xffffff`) |

**Descriptor.** 14 byte-identical `kalloc_type` views named `site.JpegRequest` occupy
`0x807b938 + 0x40*k, k = 0..13` (last: `0x807bc78`). They are identical because Apple emits one
view per allocation *site* and the runtime dedups views with the same name/size/flags into one zone
— which is why allocating with one view and freeing with another is correct, not a bug.

**Alloc sites (5)** — all use `0x807b938`, all immediately followed by `request_reset`:

| site | enclosing function | note |
|---|---|---|
| `0x9018388` | `0x901836c` | **`JpegRequest::alloc()`** — a 0x40-byte helper: `kalloc_type` → `request_reset` → return |
| `0x90188b8` | `0x9018830` | `startDecoder` (sel 1) |
| `0x90193c4` | `0x9019334` | `startDecoderExt` (sel 5) |
| `0x9019bc8` | `0x9019ad0` | `startEncoder` (sel 3) |
| `0x901a3d8` | `0x901a348` | `startDecoder2024` (sel 7) |

**Free sites (13).** **Exactly one is unconditional, and it is the only place a request is ever
freed:**

```
finish_io_gated  (0x9016aec)
  0x90170f8  adrp x0, #0x807b000 ; add x0, x0, #0xc78    ; the JpegRequest descriptor
  0x90170fc  ...  mov x1, x19                            ; x19 = the request
  0x9017104  bl   #0x903c538                             ; kfree_type(desc, req)
```

The other **12** free sites are all error paths of the form
`<setup call> -> wN ; ldr x8,[x19,#0x30] ; cbz x8,<free> ; cbz wN,<retry> ; free(desc, req)` and each
returns an error immediately afterwards. They are enumerated in §7.

**Consequence.** Because there is a single free site and it sits at the end of the `async` arm of
`finish_io_gated`, *the request can only ever be freed once per allocation* — unless
`finish_io_gated`'s `async` arm can run twice for one request, which §4 rules out.

---

## 2. Selector → handler map (PROVEN)

The userclient's dispatch table is at `0x8078860`, stride `0x28`, and the layout is
`{ function; scalarIn; structIn; scalarOut; structOut; entitlement; }`:

| sel | thunk | `structIn`/`Out` | handler | name |
|---|---|---|---|---|
| 0 | `0x9022d98` | 0 | `0x901717c` | — |
| 1 | `0x9022da4` | `0x58` | `0x9018830` | `startDecoder` |
| 2 | `0x9022dd8` | 0 | `0x9017188` | — |
| 3 | `0x9022de4` | `0x58` | `0x9019ad0` | `startEncoder` |
| 4 | `0x9022e18` | `0x1000` | `0x9019ee4` | `startEncoderExt` |
| 5 | `0x9022e4c` | `0x1000` | `0x9019334` | `startDecoderExt` |
| 6 | `0x9022e80` | `0xda0` | `0x901a9e8` | `startEncoder2024` |
| 7 | `0x9022eb4` | `0xda0` | `0x901a348` | `startDecoder2024` |
| 8 | `0x9022ee8` | 4 | `0x90165e4` | — |
| 9 | `0x9022f18` | 0 | `0x901667c` | — |

`0xda0 = 3488` and `0x1000 = 4096` match the sizes the prior document derived independently, which
confirms the table read. Selectors **6 and 7 are the only ones with `entitlement = 1`** in the
table's sixth field.

All six `start*` handlers end with the same gate call
(`ldr x0,[this+0xb8] ; … vtable[0xe8] ; blraa`) = `IOCommandGate::runAction(queue_io_gated, req)`,
so the whole submission runs **synchronously inside `externalMethod`**.

---

## 3. `finish_io_gated(req, IOReturn, core, async)` — two modes, and the free is gated (PROVEN)

`finish_io_gated` (`0x9016aec..0x901717c`) has exactly two callers, and they pass **opposite**
values of the 4th argument:

| caller | site | `x4` | mode |
|---|---|---|---|
| `begin_io_gated` (`0x9015c38`) | `0x9015e5c` | `w4 = 0` | **synchronous / error** |
| the completion wrapper (`0x90166d0`) | `0x9016744` | `w4 = 1` | **asynchronous / completion** |

**Mode `async = 0` (sync).** `0x9016b58 cbz w23, #0x9016c38` → the sync arm records the IOReturn into
`req+0x70`, sets `req+0x74 = 1`, does per-core bookkeeping, and at `0x9016db8` returns.
**No teardown, no free.**

**Mode `async = 1` (completion).** The async arm runs the per-core release work, then:

```
0x9016f70  ldr   x8, [x19, #0x10]        ; <<< THE GATE
0x9016f74  cbz   x8, #0x9016fe0          ; gate == 0  -> virtual call on [this+0xb8]; RETURN, no free
0x9016f78  mov   x0, x20
0x9016f7c  mov   x1, x19
0x9016f80  bl    #0x901b440              ; teardown helper
...
0x9017074  ldr   x0, [x19] ; … vtable[0x28]  ; release req+0x00
0x90170f8  … bl #0x903c538               ; kfree_type(req)
```

**So the request is freed only when `[req+0x10] != 0` and only on the asynchronous completion.**

`0x90166d0` (the completion wrapper) is worth recording: it is *not* a pure interrupt handler — it
loops over the two cores, then **tail-calls `begin_io_gated`** (`0x9016ac0 b #0x9015c38`) to dispatch
the next request. That is the driver's completion→dispatch hand-off.

---

## 4. `queue_io_gated(req)` — the *other* teardown trigger, and why the two cannot both fire

`queue_io_gated` (`0x9018c0c..0x9019334`) captures the gate **once, at entry**:

```
0x9018c44  ldr   x23, [x1, #0x10]        ; x23 = [req+0x10], held for the whole call
```

and decides at the end:

```
0x90191ac  cbz   x23, #0x90191b4         ; [req+0x10] == 0            -> TEARDOWN
0x90191b0  cbz   w22, #0x90191c0         ; no error                   -> return
0x90191b4  mov   x0, x20 ; mov x1, x19
0x90191bc  bl    #0x901b440              ; TEARDOWN
```

with `w22 = (dispatch result != 0)` (`0x9019190 cmp w21,#0 ; cset w22,ne`). So:

> **`queue_io_gated` tears the request down iff `[req+0x10] == 0` OR the dispatch returned an error.
> `finish_io_gated` (async) tears it down iff `[req+0x10] != 0`.**

**The two triggers test the same field with opposite polarity.** §5 shows the field is written
exactly once, at request construction, from client data — so for the lifetime of a request it is a
constant. Two cases:

* **`[req+0x10] != 0`** — the queue path tears down *only on a dispatch error*. But look at the order
  of operations in `queue_io_gated`: the hardware is started **last**:

  ```
  0x9018fd8  bl #0x9017b78     ; setupBuffersForCoding_gated        -> w21
  0x9019034  cbnz w21, #0x9019190       ; any failure here -> teardown decision, hardware NOT started
  0x901904c  bl #0x903acd8     ; decodeRequestValidation             -> w0
  0x9019160  bl #0x903b6b4     ; decodeHWRequestSetup                -> w0
  0x90191f8  bl #0x9013228     ; the Dart map
  0x9019264  bl #0x9015c38     ; <<< begin_io_gated: THE HARDWARE IS STARTED HERE
  0x901926c  mov w22, #0 ; mov w21, #0
  0x9019274  cbnz x23, #0x90191b0       ; -> w22 == 0 -> return, NO teardown
  ```

  Every error return precedes `begin_io_gated`, so an error means the hardware was never started,
  so no completion can arrive, so `finish_io_gated(async)` never runs for that request.

* **`[req+0x10] == 0`** — the queue path tears down unconditionally (see §5), and
  `finish_io_gated(async)` **cannot** tear down because it requires `!= 0`.

**⇒ The two teardown triggers are mutually exclusive by construction, and `[req+0x10]` is immutable
after construction. The "double `finish_io_gated` ⇒ double release of the client `IOSurface`" lead
of the previous document (§12, §12.5) is REFUTED: there is no reachable pair of teardowns for one
request.** The remaining question §12.5 posed ("can `finish_io_gated` be entered twice?") is
therefore moot for the release, and `finish_io_gated`'s own single free site means a double entry
would be a double free only if the *first* entry took the `!= 0` arm — which frees and returns the
request to the allocator, after which the object is no longer reachable as a request.

---

## 5. `[req+0x10]` is CLIENT-CONTROLLED — the whole point (PROVEN)

A byte-coverage sweep for every store whose address range covers `[base+0x10]` (including
overlapping `stp`/`str q`) across the entire `__TEXT_EXEC` returns **exactly one writer of the
request's `+0x10` that is not a copy from the client struct**: the request constructor's
`str wzr, [x0, #0x10]` at `0x9018534` (`request_reset`).

Everything else that writes `+0x10` in the request's context is the **client copy**:

```
startDecoder2024 (0x901a348):
  0x901a410  add x0, x21, #0xf8 ; bl #0x903caa8   ; init a lock
  0x901a418  stp x24, x25, [x21]                  ; req+0x00 = [uc+0xf0] ; req+0x08 = the userclient
  0x901a41c  ldr q0, [x19, #0x30]                 ; <<< 16 bytes from structureInput+0x30
  0x901a424  str q0, [x21, #0x10]                 ; <<< req+0x10 = *(u64*)(structureInput+0x30)
                                                  ;     req+0x18 = *(u64*)(structureInput+0x38)
  0x901a428  ldr x9, [x19, #0x40] ; str x9, [x21, #0x20]
```

(`x19` is the `structureInput` pointer, delivered by the selector thunk at `0x9022eb4`; the prior
document's `jpeg_iostruct.md` §1.1 records the same `0x30 → 0x10` mapping for all six handlers.)

**So `req+0x10` is `*(uint64_t *)(client_struct + 0x30)` — a client-chosen 64-bit value — and it
decides which of the two mutually exclusive teardown paths runs.** The same field is also the branch
selector in the hardware setup (§6).

### 5.1 The concrete consequence: a client-forced premature teardown and a leaked request

Setting `client_struct + 0x30 = 0` makes `[req+0x10] == 0`, and then `queue_io_gated`:

1. runs the whole submission, **including `begin_io_gated`** (hardware started, `0x901927c`);
2. skips the virtual call on `req+0x00` (`0x9019240 cbz x23, #0x901927c`);
3. falls into the teardown at `0x90191b4` — **unmapping the DMA and releasing the descriptors and
   IOSurfaces while the hardware is running**;
4. and `finish_io_gated(async)` will never free the request (its free is gated on `!= 0`), so the
   **0x558-byte `kalloc_type` object is leaked, one per accepted call.**

Two honest qualifications:

* **The premature teardown is partly mitigated.** The teardown helper `0x901b440` first waits:
  `0x901b4e0 mov w24,#0x64` × `bl 0x903c598` (a 10 ms sleep) → a bounded **~1 second** delay before
  the unmap (`0x901b4f8`). A normally-completing request finishes inside that window. The wait is
  bounded, not a hardware-idle condition — the loop exits on a counter (`[this+0x130]`/`[this+0x138]`),
  not on a device state — so it is a soft guard, not a synchronisation.
* **The leak is the solid half.** The single-free-site + gate argument is purely static and does not
  depend on timing: with `[req+0x10] == 0` there is **no** code path that reaches `kfree_type` for
  that request.

**Classification: a client-controlled kernel heap leak (DoS), plus a client-forced early DMA
teardown that is mitigated by a 1-second delay. Neither is an LPE.**

---

## 6. The caller-struct alias — present, and currently INERT (REFUTED as a UAF, with a residual hazard)

`jpeg_iostruct.md` §3 candidate **C3** describes the driver "aliasing the caller's struct" when the
`0x30` field is zero, and rates it a data-integrity issue. This pass confirms the code *and* refutes
its exploitability, in both directions. Only the two **decoder** variants have it
(`startDecoderExt` sel 5, `startDecoder2024` sel 7).

```
startDecoderExt (0x9019334):                       startDecoder2024 (0x901a348):
  0x9019620  add x23, x19, #0x84                     0x901a634  add x23, x19, #0x84
  0x9019624  cbz x8, #0x901965c   ; x8 = client+0x30 0x901a638  cbz x8, #0x901a678
  0x9019628  add x0, x21, #0x4d8                     0x901a63c  add x0, x21, #0x4d8
  0x901962c  bl  #0x9019954       ; vector::resize    0x901a640  bl  #0x9019954
  0x9019630  ldr x24, [x21,#0x4d8] ; begin            0x901a644  ldr x25, [x21,#0x4d8]
  0x9019634  ldr x26, [x21,#0x4e8] ; cap              0x901a648  ldr x8,  [x21,#0x4e8]
  0x9019638  and w25, w25, #0xffc                    0x901a650  and w26, w26, #0xffc
  0x9019648  bl  #0x903cb08       ; memcpy           0x901a660  bl  #0x903cb08   ; memcpy
  0x901965c  str x23, [x21,#0x4c8]   <<< ALIAS        0x901a678  str x23, [x21,#0x4c8]   <<< ALIAS
  0x9019660  mov w8, #0x3df                          0x901a67c  mov w8, #0x300
  0x9019664  str x8,  [x21,#0x4d0]                   0x901a680  str x8,  [x21,#0x4d0]
```

So when `client+0x30 == 0` the driver **skips the heap copy** and parks
`(structureInput + 0x84, 768 | 991)` in `req+0x4c8` / `req+0x4d0`. The two representations are
resolved downstream in the hardware setup:

```
RequestHandling::encodeHWRequestSetup (0x903b6c8):
  0x903b7f0  ldr x9, [x19, #0x10]      ; <<< the same client-controlled gate
  0x903b7f4  cbz x9, #0x903b810
  0x903b7f8  ldr x9,  [x19, #0x4d8]    ; heap path: vector.begin
  0x903b7fc  ldr x10, [x19, #0x4e0]    ;            vector.end
  0x903b800  sub x10, x10, x9 ; asr x10, x10, #2
  0x903b808  stp x9, x10, [x19, #0xe8] ; (ptr,count) -> req+0xe8 / req+0xf0
  0x903b80c  b   #0x903b81c
  0x903b810  add x9, x19, #0x4c8       ; alias path
  0x903b814  ldr q0, [x9]
  0x903b818  stur q0, [x19, #0xe8]     ; req+0xe8 = req+0x4c8 ; req+0xf0 = req+0x4d0
```

**The transient-buffer argument.** `structureInput` is the ioctl's own kernel buffer, valid only for
the duration of `externalMethod`. The driver's *other* branch copies the bytes into a heap vector —
which only makes sense if the source is transient. And the request demonstrably outlives the call
(it is completed by the interrupt, and `finish_io_gated` runs then). So `req+0x4c8` is a stale kernel
pointer to a freed buffer parked inside a long-lived object — the exact shape of a use-after-free.

**Why it is nevertheless not one, in this build (three independent checks):**

1. **The only consumer of `(req+0x4c8, req+0x4d0)` is `request_reset` — and `request_reset` is only
   ever called on a freshly allocated request.** `request_reset` (`0x90183ac`) contains the
   zero-fill:

   ```
   0x901849c  ldr x8,  [x19, #0x4c8]      ; ptr
   0x90184a0  ldr x10, [x19, #0x4d0]      ; count
   0x90184a4  add x9, x8, x10, lsl #2
   0x90184b8  cmp x10, #1
   0x90184bc  b.lt #0x90184dc             ; count < 1 -> skip
   0x90184cc  str wzr, [x8], #4           ; <<< memset(ptr, 0, count*4)
   ```

   Its callers are exactly six, and **every one is immediately after `kalloc_type` on the fresh,
   zeroed object**: `0x9018398` (in `JpegRequest::alloc`), `0x90188d0`, `0x90193dc`, `0x9019bdc`,
   `0x901a3f0`, and — verified by a full data-section scan for any pointer to `0x90183ac` — **there
   is no indirect reference to it anywhere in the kext's `__DATA`/`__DATA_CONST`/`__TEXT`.** On a
   fresh object `req+0x4d0 == 0`, so `b.lt` skips the store. **The zero-fill never executes with a
   non-zero pointer.**

2. **The resolved pair `(req+0xe8, req+0xf0)` is never dereferenced either.** Across the whole
   kext it is read in exactly two places: `showRequestInfo` (`0x901cb58`, at `0x901cec8` /
   `0x901cedc`) where both words are formatted into a diagnostic log line, and the register-bank
   writer `0x901bc6c`, which *increments* `[x19+0xe8]` / `[x19+0xf0]` — and whose `x19` is
   `this + (w2 == 1 ? 0x198 : 0xa0)` (`0x901bc94`), i.e. a hardware register block, **not the
   request**. Neither dereferences the pointer.

3. **The alias does not survive to the hardware.** `encodeHWRequestSetup` runs inside
   `queue_io_gated`, i.e. inside `externalMethod`, so even if a later stage consumed `(0xe8, 0xf0)`
   it would still be inside the buffer's lifetime.

**⇒ C3 is a latent hazard, not a live use-after-free.** The correct statement is: the driver parks a
pointer into a transient ioctl buffer in a persistent object, stores it in a second field, and
**one added consumer away from a UAF**; today it is only logged and counted. It should be reported
as a hardening defect with a one-line trigger, not as a vulnerability. The prior document's framing
("data-integrity issue ... low severity") was too *strong* about impact and too *weak* about cause —
the reason it is safe is not the struct's extent, it is that nothing reads the pointer.

**One functional consequence worth recording:** with `client+0x30 == 0`, `req+0x4d8` (the heap
vector) is left empty, and `encodeHWRequestSetup` reads the *vector* on the other branch — so the
client's `newHeader` is silently dropped. The partial-decode header path is inconsistent between its
two representations. That is a correctness bug in the same code.

---

## 7. The teardown releases FOUR OSObjects and clears only TWO (PROVEN — extends §12)

The prior document's §12.1 said the teardown releases `req+0x2b8` and never clears it. Reading the
whole function (`0x9017fe4..0x90182b4`) shows the pattern applies to **two** objects, and that the
two that *are* cleared are cleared precisely because they are the ones the driver null-checks:

| field | object | release | cleared? |
|---|---|---|---|
| `req+0x2c8` | descriptor A (`IOBufferMemoryDescriptor`) | `0x9018060` `vtable[0x28]` | **yes** — `0x9018080 str xzr` |
| `req+0x2b8` | **IOSurface A** | `0x90180c8` `vtable[0x28]` | **no** |
| `req+0x2d0` | descriptor B | `0x90181a0` `vtable[0x28]` | **yes** — `0x90181a4 str xzr` |
| `req+0x2c0` | **IOSurface B** (multi-plane) | `0x90181ec` `vtable[0x28]` | **no** |

`req+0x2b8` / `req+0x2c0` are the two planes of the client-supplied `IOSurface`; `req+0x2c8` /
`req+0x2d0` are the descriptors obtained from `[IOSurface+0x30]` (the prior document's §2). The
descriptor fields are cleared, which is exactly the defence that makes a second `unmapMemoryDescriptor`
harmless; the two IOSurface fields have no equivalent guard, which is what made §12's lead
interesting — **and §4 is what closes it.**

---

## 8. LPE assessment — the honest position after this pass

| question | answer |
|---|---|
| Full LPE on 24A435 from this chain? | **Not demonstrated, and this pass removes two of the three remaining candidate mechanisms.** |
| Double release of the client IOSurface (prior §12)? | **REFUTED.** The two teardown triggers are gated on the same immutable, client-set field with opposite polarity, and every `queue_io_gated` error return precedes `begin_io_gated`, so no completion can follow. |
| Use-after-free via the caller-struct alias (prior C3)? | **Not live.** The only consumer of the aliased pair is a reset that runs exclusively on freshly allocated (zeroed) objects; the resolved pair is only logged and counted. Latent hazard. |
| Client-controlled defect found? | **Yes — a kernel heap leak of one 0x558-byte `kalloc_type` object per accepted call by setting `client_struct+0x30 = 0`, plus a client-forced early DMA teardown mitigated by a ~1 s wait. DoS class.** |
| `_dmaReferences` wrap (prior §9)? | **Unchanged** — reachable on the unbounded `IOBufferMemoryDescriptor` implementation, still needs 65,535 net unbalanced increments on one persistent descriptor, still no memory-safety consequence demonstrated. |
| Privilege boundary crossed anywhere? | **No.** The acting process is `ImageIOXPCService` (a `platform-application` system service). |

**The exact bar that remains.** For a *full* LPE from this driver one of the following has to be
shown, and none of them is:

1. an **imbalance** in `_dmaReferences` that is large and cheap (the leak is +1 per failed
   prepare; the wrap needs 65,535 of them on one persistent descriptor, then one genuine
   prepare + its completion);
2. a **consumer** of the aliased `(req+0x4c8, req+0x4d0)` / `(req+0xe8, req+0xf0)` pair that
   dereferences it — which would immediately turn §6 into a use-after-free of a freed ioctl buffer,
   reachable from the client with one field; or
3. a **second free of the request** — which requires a `finish_io_gated(async)` entry that is not
   preceded by the `queue_io_gated` teardown, and §1's single free site plus §4's exclusivity make
   that the whole remaining question.

Of these, **(2) is the cheapest to close and the most valuable**: it is a bounded read of the two
callers of `encodeHWRequestSetup` plus the partial-decode path, and the driver's own two
representations of the same array are inconsistent, which is where a consumer bug would live.

---

## 9. Artifacts

All under `analysis/priv24A435/lpe27gm/`.

| file | purpose |
|---|---|
| `jt.py` | kext/kernelcache access: **exact function starts from `LC_FUNCTION_STARTS`**, sections, `__cstring` index, `iter_insns` (a linear sweep that does **not** stop at an undecodable word — a plain `disasm()` truncates at the first data blob and silently hides most of the segment), direct arm64e pointer decode, `stub_target` |
| `dump.py` | dump a function with `--fn`, find `--callers`, locate a `--str` and its code xrefs |
| `scan.py` | instruction-pattern scanner: `--store/--load/--any <hex_off>`, `--mnem`, `--stub` |
| `sym.py` | resolve an `__auth_stub` → GOT slot → target VA → owning kext (VA authority = the extracted kexts' `LC_SEGMENT_64`) |
| `kref.py` | map every `__kalloc_type` site descriptor to the code sites that materialise it and the call that consumes it (the alloc/free lifecycle map) |
| `dis/*.txt` | full disassembly of `finish_io_gated`, `begin_io_gated`, the completion wrapper, `queue_io_gated`, the teardown, the teardown helper |

Reusable traps, now encoded:

* **`__DATA_CONST` section `offset` ≠ segment-derived offset** in the extracted kexts (differ by
  `0xC0`); use the **segment** mapping.
* **The extracted kexts have no `LC_DYLD_CHAINED_FIXUPS`** — decode pointer words directly with the
  kernelcache bias.
* **`kalloc_type_view`: site string at `+0x10`, type name at `+0x20`, flags at `+0x28`, size at
  `+0x2C`.**
* **A plain capstone `disasm()` over a segment truncates at the first data blob.** Any whole-segment
  scan must advance one instruction on failure and continue.
* Views in `__kalloc_type` are deduplicated at runtime by (name, size, flags) — so allocating with
  one view and freeing with a byte-identical sibling view is correct, not a bug.

---

## 10. What is NOT changed

The prior document's §1–§8 conclusions about `IOBufferMemoryDescriptor`, the unbounded `ldaddh` at
`0xb3409dc`, the `fMapper`-gated op-3 pin, and the single op-5 issue site at `0xb3375f8` are
untouched by this pass and were not re-derived. The reachability of the JPEG chain from
`ImageIOXPCService` (§11–§15) likewise stands.
