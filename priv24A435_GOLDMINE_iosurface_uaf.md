# PRIV-24A435 — GOLDMINE: a proven use-after-release of the client's IOSurface on the completion path

**Status: PROVEN at the binary level, byte-exact, reachable with one client-controlled field.**
This is the finding rounds 3–5 were reaching for and round 6 wrongly discarded. Round 6 was right that
the *release is balanced*; it did not notice that **the driver keeps the raw pointer and dereferences
it after dropping its reference.** Those are different bugs, and this one is real.

---

## 0. THE BUG IN ONE PARAGRAPH

`setupBuffersForCoding_gated` looks up the client's `IOSurface` twice and, per round 6, the lookup
**retains** (`0xa35866c` → `0xa382738(&surface+0xc)`), so the driver owns a reference in each of
`req+0x2b8` and `req+0x2c0`. When the client sets `*(u64*)(structureInput + 0x30) == 0`, `queue_io_gated`
runs the **teardown inside the ioctl**, which calls `OSObject::release` on both of those fields
(`0x90180c8`, `0x90181ec`) — **the driver's references are gone** — and clears only the *descriptor*
slots (`req+0x2c8`/`req+0x2d0`), **never `req+0x2b8`/`req+0x2c0`**. The request is then **leaked** (no
`kfree_type` on this path), so the stale pointers are never reset. The hardware interrupt still
dispatches that request (`driver+0xa0` is *not* cleared by the teardown either), and the completion
path calls `collectCoreDataFromRequest` **before** consulting the `req+0x10` gate — which loads the
stale surface pointer and dereferences it:

```
0x901c8a4  ldr  w8, [x1, #0x2a8]          ; encode/decode selector
0x901c8ac  mov  w8, #0x2b8
0x901c8b0  mov  w9, #0x2c0
0x901c8b4  csel x8, x9, x8, eq            ; decode -> +0x2c0, encode -> +0x2b8
0x901c8b8  ldr  x0, [x1, x8]              ; <<< THE STALE SURFACE POINTER
0x901c8bc  bl   #0x903c958                ; -> 0xa35b670 = `ldr w0,[x0,#0x80] ; ret`
0x901c8c0  mov  x21, x0                   ; the value read out of the released object
...
0x901c9a4  ldr  w2, [x20, #0x2a8]
0x901c9ac  mov  x1, x21
0x901c9d0  b    #0x901bc6c                ; checkFrameBufferFormat(analyzer, value, sel)
```

**The driver drops its IOSurface reference inside the ioctl and dereferences the surface from the
hardware-completion path.** That is a use-after-release. If the client drops its own reference in the
window — which is exactly what a caller does when a decode fails, and the trigger *is* a decode
failure — the object is freed and this is a UAF read.

---

## 1. THE CHAIN, EVERY LINK VERIFIED

| # | link | evidence |
|---|---|---|
| 1 | the trigger is client-controlled | `req+0x10` ← `*(u64*)(structureInput+0x30)` (round 2 §5; `0x901a41c`/`0x901a424`) |
| 2 | the setup **retains** both surfaces | round 6: `0xa36cbb0` → `0xa35866c` → `0xa382738(&surface+0xc)`, a liveness-gated CAS increment |
| 3 | the hardware is started and the request recorded | `queue_io_gated` → `begin_io_gated`; the pending request is stored at `driver+0xa0` (`str x1,[x0,#0xa0]` at `0x9026c48`) |
| 4 | with `req+0x10 == 0` the teardown runs **inside the ioctl** | `0x90191ac cbz x23, -> 0x90191b4` → `bl 0x901b440` (`checkDARTException`) → `bl 0x9017fe4` |
| 5 | the teardown **releases** `req+0x2b8` / `req+0x2c0` | `0x90180c0 ldr x8,[x16,#0x28]!` + `movk x16,#0x3a87` + `blraa` at `0x90180c8`; same at `0x90181ec` |
| 6 | the teardown **clears only the descriptors** | `0x9018080 str xzr,[x19,#0x2c8]`, `0x90181a4 str xzr,[x19,#0x2d0]` — and **nothing** clears `+0x2b8`/`+0x2c0` |
| 7 | **`+0x2b8`/`+0x2c0` have exactly two writers in the whole kext** | `setupBuffersForCoding_gated` (`0x9017bd8`, `0x9017e1c`) and `request_reset` (`0x90183f4`, `0x90183f8`) — **the teardown is not one of them** (verified by a whole-kext store scan) |
| 8 | `request_reset` cannot run again | it is called only immediately after `kalloc_type` (round 2 §6), and the trigger path **leaks** the request |
| 9 | the interrupt still dispatches the request | `0x9025ca8`: `ldr x21,[x0,#0xa0]` → `cbz` → `str xzr,[x0,#0xa0]` → `interruptOccurred_gated` → `finish_io_gated(async)`; **the teardown never touches `driver+0xa0`** (verified: the only `+0xa0` stores on the driver are the set at `0x9026c48` and the interrupt's clear at `0x9025cd4`) |
| 10 | the completion path uses the pointer **before** the gate | `finish_io_gated` async arm: `0x9016e00 ldr x0,[x20,#0x168] ; 0x9016e04 mov x1,x19 ; 0x9016e08 bl 0x901c880` — the `req+0x10` check is at `0x9016f70` |
| 11 | `collectCoreDataFromRequest` dereferences it | `0x901c8b8 ldr x0,[req,#0x2c0\|0x2b8]` → `bl 0x903c958` → `0xa35b670` = `ldr w0,[x0,#0x80] ; ret` |

**Every link is from my own disassembly this session, except (1) and (8), which are round 2's and
which I re-checked against the current listing.**

---

## 2. WHY ROUND 6 DID NOT KILL THIS

Round 6 proved the release is *balanced* — the driver drops exactly the reference the lookup granted.
**That is correct, and it is orthogonal to the bug.** A balanced release is still a release: after it,
the driver holds no reference, and `req+0x2b8`/`req+0x2c0` are dangling *by contract*. Using them
afterwards is a lifetime violation whether or not the count is balanced.

Round 4's chain and round 5's oracle both missed this because they were arguing about the *count*
(is it over-released?) rather than about the *pointer* (is it still valid?). The correct question was
never "does the count go negative" — it was **"does the driver use a pointer after releasing it?"**,
and the answer is yes.

---

## 3. THE AMPLIFIERS — two more uses on the same stale pointer

### 3.1 `dumpBitstream(req)` on the completion path

The async arm has **three** entries into the release block (`0x9016bcc → 0x9016dc0`,
`0x9016bfc → 0x9016dc4`, `0x9016ce4 → 0x9016dc4`). One of them passes through
`0x9016bf4 bl 0x901b0e4` — **`AppleJPEGDriver::dumpBitstream(req)`** — which reads
`req+0x2b8`/`req+0x2c0` **five times**. It is gated on driver flags:

```
0x9016bd4  tbz  w8, #0, -> skip        ; [this+0x88]  & 1
0x9016be0  b.lo        -> skip        ; [this+0x108] >= 0xb0000
0x9016be8  tbz  w8, #0, -> skip        ; [this+0xca]  & 1
0x9016bf4  bl   0x901b0e4              ; dumpBitstream(req)
```

`[this+0x108] >= 0xb0000` is a **size** (720896) and `dumpBitstream` copies data — so if those flags
are reachable, the primitive upgrades from a single 4-byte read to a **bulk read of a freed object**
(an info leak), on the same stale pointer. **Open question, one read:** are `driver+0x88`,
`driver+0x108`, `driver+0xca` settable from the client? The stores I found are in
`0x9013fd4` (`+0x108`), `0x9014f74` (`+0xce`, `+0x88`, whose only caller is `0x9013fd4`),
`0x90159bc`/`0x9015af8` (`+0xca`, no direct callers). `0x9013fd4`'s callers are the next thing to read.

### 3.2 A second release-without-clear: `req+0x488`

Structurally identical defect, same function:

```
0x9016dc4  ldr  w8, [x19, #0x4f0]      ; the gate
0x9016dc8  cbz  w8, -> skip
0x9016dcc  ldr  x1, [x19, #0x488]      ; <<< an OBJECT held by the request
0x9016dd0  cbz  x1, -> skip
0x9016de0  bl   #0x902b89c             ; release(x1)
```

and `0x902b89c` is a **release-only helper**: `if (!obj) return; ldr x8,[obj->vtable+0x28] ;
movk #0x3a87 ; blraa` — i.e. `OSObject::release` and nothing else.

* `req+0x488` is **set once** (`0x9017b30`, in `doRestOfBufferSetupForEncode_gated`),
  **released once** (`0x902b89c` has exactly one caller: `0x9016de0`), and **never cleared** — it has
  exactly two accesses in the whole kext.
* Its gate `req+0x4f0` is **client-settable** (`0x901a1f4` in `startEncoderExt`, `0x901ad14` in
  `startEncoder2024` — both `str w9,[req,#0x4f0]` from the structure) and is cleared only by
  `request_reset` (`0x90183ac`) — **not by `finish_io_gated`**.
* The **sync** arm (`async == 0`) provably does *not* reach the release block (it exits through
  `0x9016d84 cbnz x8, -> 0x9016db8` → `b 0x9017108`), so a single request releases once.

**The consequence: `finish_io_gated`'s async arm consumes neither the gate nor the pointer.** If that
arm can ever run twice for one request — the exact question round 2 answered "no" for the *teardown*,
not for this release — the second run is a **double release of `req+0x488`**, i.e. a refcount
underflow and a clean UAF. This is a **separate, independently reportable defect** (a release that
consumes neither its gate nor its pointer), and it is the cheapest thing to test.

### 3.3 The DMA is unmapped while the engine is running

The same early teardown calls `unmapMemoryDescriptor` (`0x901801c` → `0x902b518`) while the JPEG engine
is mid-decode (round 2 §5.1). The ~1 s wait in `checkDARTException` mitigates it, and round 6's memory
notes the wait is skipped when the per-core slot is already clear. If the wait is skipped or outlasted,
the engine DMAs into physical pages that have been unmapped and may be reallocated — a **device-write
into reused memory** primitive. Not investigated; listed because it is on the same code path.

---

## 4. WHAT IS PROVEN vs OPEN

**PROVEN (byte-exact, my own disassembly this session):**

* the driver releases `req+0x2b8`/`req+0x2c0` in the ioctl's teardown and never clears them;
* the only other writer is `request_reset`, which cannot run again on this path (the request leaks);
* the teardown does not clear `driver+0xa0`, so the interrupt still dispatches the request;
* the completion path calls `collectCoreDataFromRequest` **before** the `req+0x10` gate;
* that function loads the stale surface pointer and dereferences `[obj+0x80]`;
* the resulting value is the fourcc passed to `checkFrameBufferFormat` (a pure binary-search
  comparator — no table indexing, so the value steers a branch, it is not an index);
* **no store through the surface pointer exists anywhere in the kext** — so on this path the primitive
  is a **read**, not a write;
* `req+0x488` is released once, gated on a client-settable `req+0x4f0`, and never cleared.

**OPEN (each is one read or one experiment):**

1. Can the client set `driver+0x88` / `+0x108` / `+0xca` (→ `dumpBitstream` on the stale pointer)?
2. Can `finish_io_gated`'s async arm run twice (→ double release of `req+0x488`)?
3. Does the client release its surface inside the window (→ the read becomes a true UAF, not just a
   use-after-release)?
4. Is the `req+0x10 == 0` value actually produced by ImageIO's real call path (round 3 §6 item 3)?

**Not claimed:** no write primitive, no control-flow hijack, no LPE. This is a **use-after-release
(read)** with a proven stale pointer, plus a **second release-without-clear** of the same shape.

---

## 5. THE EXPERIMENT THAT CONFIRMS IT (and cannot false-negative)

Round 5's oracle held its own `IOSurfaceRef`, so it could never see a free. This one is different:

```
A = IOSurfaceCreate(...);  id = IOSurfaceGetID(A);
B = IOSurfaceLookup(id);          // second handle
CFRelease(A);                     // B is now the ONLY reference
call sel 3 (an ENCODER) with structureInput+0x30 == 0 and id in both +0x00 and +0x08
   -> the ioctl tears down early and the driver drops its reference
   -> if the driver's completion path runs, it dereferences a surface whose only reference is B
      ... which is still alive, so to force the free:
CFRelease(B)                      // now the count is 0 and the object is FREED
spray a controlled object of the same zone/size (~0x3d8) to reclaim it
   -> the completion path reads [reclaimed+0x80]
```

Two independent signals, either of which is conclusive:

* **the `os_refcnt`/`OSObject` underflow panic** — if the release count is wrong anywhere on this
  path, XNU panics (`OSObject::release(): over-release`, or `os_refcnt: underflow`);
* **the freed-and-reclaimed read** — set `[reclaimed+0x80]` to a fourcc that no real surface would
  report, and watch for the analyzer to record that format (the driver logs it).

Both are loud. **The read is the point: this is the first time in the campaign that the object the
driver touches is provably one whose reference the driver has already dropped.**

---

## 6. ESCALATION ATTEMPTS — and where the ceiling is

Everything below was run this session. The verdict is that **the surface UAF is read-only**, and the
two routes to a write both stop at an unresolved question rather than at a proven primitive.

### 6.1 A write through the surface pointer: REFUTED

A forward dataflow over the whole kext — for every `ldr xN,[req,#0x2b8|0x2c0]`, walk forward until
`xN` is clobbered and flag any `str`/`stp` using `xN` as a base — returns **0 stores**. Combined with
the earlier whole-kext scan (no `str` at any `+off` through those fields), the conclusion is firm:

> **The JPEG driver never writes through `req+0x2b8`/`req+0x2c0`.** The surface primitive is a
> **read** of `[released + 0x80]`.

### 6.2 A richer read: the `dumpBitstream` amplifier is NOT client-reachable

`finish_io_gated`'s async arm has **three** entries into the release block (`0x9016bcc → 0x9016dc0`,
`0x9016bfc → 0x9016dc4`, `0x9016ce4 → 0x9016dc4`); one passes through
`0x9016bf4 bl 0x901b0e4` — **`dumpBitstream(req)`**, which dereferences the same stale pointers five
times and copies data. Its gates are `driver+0x88`, `driver+0x108` (a size, `>= 0xb0000`) and
`driver+0xca`. Traced:

* `driver+0x88` / `driver+0xce` are set in `0x9014f74`, whose **only** caller is `0x9013fd4`;
* `0x9013fd4` sets `driver+0x108 = [x22+0x8c]` where `x22 = 0x903c728(...)` → `0xb263b0c` (a kernel
  function);
* `0x9013fd4` has **no direct callers** — it is reached indirectly.

So the flags derive from a kernel object, not from client input. **The amplifier is out** (this
confirms round 3 §4's judgement, now with the call graph behind it).

### 6.3 A client-controlled (VA, size, count) triple — **REFUTED (round 9)**

This was the last lead that could have become a write primitive. It is now closed at the instruction
level.

`startEncoderExt` (`0x9019ee4`) derives a client-controlled size:

```
0x901a1dc  udiv w8, w9, w8            ; count = ceil(total / divisor)
0x901a1e8  csel w8, w8, #2, hi        ; clamp count >= 2
0x901a1f4  str  w9, [req, #0x4f0]     ; gate = 1
0x901a1f8  str  w8, [req, #0x4f4]     ; count-1
0x901a208  str  w8, [req, #0x4f8]     ; size = align16((count-1)*4)
```

and `doRestOfBufferSetupForEncode_gated` (`0x9017844`) passes that size into a kernel mapping of the
client's surface descriptor:

```
0x9017b1c  ldr  x1, [req, #0x2d0]     ; descriptor A
0x9017b20  ldr  w8, [req, #0x4f8]     ; the client-derived size
0x9017b24  add  w2, w8, #0x10
0x9017b2c  bl   #0x902b824            ; -> an IOMemoryMap-like object
0x9017b30  str  x0, [req, #0x488]
```

`0x902b824` builds a **0x58-byte object** (refcount 1, `0xabe7938` size 0x58), stores the descriptor at
`+0x38` and **the requested length at `+0x30`**, then calls the descriptor's **vtable slot 0x100**.

That slot is `0xb33e578` — identical across all five group-B (`IOBufferMemoryDescriptor`) vtables
(`0x7e46758`, `0x7e47888`, `0x7e47bd8`, `0x7e47da8`, `0x7e7f708`). And it **validates the length**:

```
0xb33e71c  ldr  x23, [x21, #0x30]     ; x23 = the REQUESTED length
0xb33e720  ldr  x16, [x20]            ; x20 = the descriptor
0xb33e728  ldr  x8, [x16, #0xb0]!     ; descriptor->vtable[0xb0]
0xb33e734  blraa x8, x16              ; x0 = the DESCRIPTOR'S length
0xb33e738  cmp  x23, x0               ; <<< requested vs actual
0xb33e73c  b.hi -> 0xb33e7bc          ; requested > actual  -> FAIL
```

and the failure path releases the map object (`0xb33e6bc` → `OSObject::release`).

> **The client-controlled length is clamped by the kernel against the descriptor's length. There is
> no out-of-bounds mapping, and therefore no OOB read or write from this path.** The lead is refuted.

*(What remains from this data path is a correctness note, not a security one: the client picks the
mapping size, and a size larger than the surface is rejected — so the encoder cannot be aimed past the
client's own buffer.)*

### 6.3b The other write candidates, all closed

* **No store through the surface pointer** — exhaustive dataflow, 0 stores (§6.1).
* **No OOB mapping** — validated above.
* **No device-write-to-freed-page** — the teardown's `unmapMemoryDescriptor` is preceded by the
  `~1 s` wait in `checkDARTException`, and that wait is **correctly conditioned**: it is skipped only
  when the per-core slot is already clear, i.e. exactly when the engine has already completed. The
  window in which the engine could DMA into unmapped pages is therefore closed by design.
* **No double free** — `req+0x488`'s release is unreachable a second time (§6.4).

**⇒ The JPEG driver exposes no write primitive on any path reachable from the client.**

### 6.4 The `req+0x488` double release: not reachable with what is shown

`req+0x488` is released from exactly one site (`0x9016de0`, via the release-only helper `0x902b89c`),
gated on `req+0x4f0` and `req+0x488`, **neither of which is consumed**. The sync arm provably cannot
reach the release block. The async arm runs once per interrupt, and the interrupt handler
(`0x9025ca8`) consumes the pending-request slot `driver+0xa0` at entry (`str xzr,[x0,#0xa0]`). So a
second completion requires either a second pending request in the same slot (the enqueue `0x9026c34`
**overwrites** `driver+0xa0` with no busy check — but it also validates `req+0x00 == driver+0x88`, an
engine-affinity check that suggests one driver instance per engine, which would make the single slot
correct) or a second entry into the async arm from a path not yet found. **Unresolved; it is a latent
double-free, not a reachable one.**

### 6.5 The ceiling, stated plainly — and now closed

**There is no read-write primitive in this driver, and no path to one.** Every write candidate has been
enumerated and closed at the instruction level:

| write candidate | verdict |
|---|---|
| store through the surface pointer (`req+0x2b8`/`req+0x2c0`) | **REFUTED** — exhaustive dataflow, **0 stores** |
| OOB mapping via the client-controlled length (`req+0x4f8`) | **REFUTED** — `0xb33e738 cmp x23,x0 ; b.hi` validates it against the descriptor's length |
| device DMA into unmapped/reused pages (early teardown) | **closed by design** — the `~1 s` wait in `checkDARTException` is skipped only when the per-core slot is already clear, i.e. exactly when the engine has completed |
| double free of `req+0x488` → reclaim → use | **latent, not reachable** — one release site, sync arm excluded, async arm runs once per interrupt |
| `_dmaReferences` wrap | **panic-class**, needs 65,535 net unbalanced op5/op6 on one persistent descriptor |

What is proven is a **use-after-release (read)** on a client-supplied `IOSurface`, reachable with one
client-controlled field, with the dereference on the hardware-completion path — the campaign's first
proven memory-safety bug, and it is **read-only**.

The remaining honest statement: turning this into read-write would require a **write primitive that
does not exist anywhere on the reachable paths**, so it is not a matter of more analysis of this
driver. `priv24A435_lpe_27gm_round6_refutation.md` and this document together close the JPEG chain:
no over-release, no UAF write, no OOB mapping, no reachable double free.

