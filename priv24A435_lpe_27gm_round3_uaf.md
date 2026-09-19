# PRIV-24A435 — round 3: the early IOSurface release, and the completion-path use-after-release

Continuation of `priv24A435_lpe_27gm_round2.md`. Round 2 concluded that the two defects it found
(a client-controlled heap leak and a client-forced early DMA teardown) were DoS-class, and that the
one remaining lead was "find a consumer that dereferences the aliased pointer". **This round found
the consumer — and it is not the aliased pointer. It is the IOSurface.**

The vehicle is a defect round 2 did *not* report: with one client-controlled field set, the driver
**drops its own reference to the client's `IOSurface` inside the ioctl and then dereferences the
still-stored pointer later, from the completion path.** That is a use-after-release, and the
interval between the release and the use contains a driver-inserted **~1 second sleep**.

Everything below is from the 24A435 kernelcache and the extracted kext binaries.

---

## 0. HEADLINE

1. **The driver never retains the `IOSurface`; it releases it anyway.** `setupBuffersForCoding_gated`
   obtains the surface from `IOSurfaceRoot` (`0x903c6e8` → `0xa36cbb0`) and stores it at
   `req+0x2b8` / `req+0x2c0`. The only other thing it does with it is `0x903c888` **with a mode
   argument** — a lock, not a retain (the target locks `obj+0x50` and tests a flag at `obj+0x3d0`).
   The 4-object release inside `checkDARTException` then calls **`OSObject::release`** on both
   fields (`vtable[0x28]`, `0x90180c8` / `0x90181ec`). The reference it drops is the one the
   *lookup* returned; the request never held an independent one.

2. **The release happens early, and the pointer is used afterwards.**
   `queue_io_gated` tears the request down *inside the ioctl* when `[req+0x10] == 0`. The pointer at
   `req+0x2b8`/`req+0x2c0` is **not cleared**. Later, from the hardware completion,
   `finish_io_gated` calls **`AppleJPEGCoreAnalyzer::collectCoreDataFromRequest(req)`**
   (`0x9016e08` → `0x901c880`), which does

   ```
   0x901c8a4  ldr  w8, [req, #0x2a8]
   0x901c8b4  csel x8, x9, x8, eq        ; x8 = (decode) ? 0x2c0 : 0x2b8
   0x901c8b8  ldr  x0, [req, x8]         ; <<< the surface the driver just released
   0x901c8bc  bl   #0x903c958            ; <<< into com.apple.iokit.IOSurface (0xa35b670)
   ```

3. **The window is ~1 second, and the client owns the other reference.** Between the release and the
   dereference sits the teardown's bounded wait — `0x901b4e0 mov w24,#0x64` × `IOSleep(10)`
   (`0x901b4fc`) — so the interval is a driver-inserted **1-second** sleep, not a few instructions.
   The only remaining reference to the surface is the **client's**, and the client is free to drop
   it: the ioctl returns success immediately after the release.

4. **The trigger is one client-controlled field.** `[req+0x10]` is copied verbatim from
   `structureInput + 0x30` (`0x901a424` / `0x9019620`), and it is the sole selector between
   "release at completion" (safe) and "release now, use later" (unsafe).

5. **The reference the driver drops was never taken by the driver.** A sweep of all 30 IOSurface
   entry points the kext uses, plus every call site, shows the driver makes exactly four kinds of
   call on the surface: the lookup (×2), a **lock** (`0x903c888`, which takes a *mode* argument),
   and the teardown's unlock (×4) + `OSObject::release` (×2). **There is no retain anywhere.** And
   the lookup itself contains **no atomic reference-count increment** on any path
   (`0xa36c868…0xa36cc00` scanned for `ldadd`/`ldadda`/`stadd`/`swp`/`cas`: none). If the lookup
   returns a borrowed pointer, the teardown's release is an **over-release**, and the chain is a
   **deterministic UAF with no race at all** — on the normal path too.

**Verdict: a release of a reference the driver never took, on a client-supplied kernel object,
followed by a dereference of the still-stored pointer one second later from the completion path.**
One function read decides whether it is a deterministic over-release or a wide-window race. It is
the strongest finding in this campaign and it is not yet demonstrated end-to-end.

---

## 1. Recovered symbol map — a full name table with no symbols

Round 2 was working from partial names. This round recovered **116 named functions** for the
stripped kext, and two of round 2's attributions were wrong because of it.

**The technique.** Apple kexts pass the demangled function signature as a `%s` argument to every
`os_log` call, and that string lives in `__cstring`:

```
0x9016c00  adrp x8, #0x753c000 ; add x8, x8, #0x778   ; "IOReturn AppleJPEGDriver::finish_io_gated(...)"
0x9016c08  stp  x8, x23, [sp]                         ; pushed as the %s argument
0x9016c1c  adrp x3, #0x7541000 ; add x3, x3, #0x8d7   ; the format string (__os_log)
0x9016c28  bl   0x903ca78                             ; the log call
```

So every function that logs its own name can be named by finding the `adrp+add` that materialises
its signature string. `symmap.py` does this over all 270 `__cstring` strings that contain `::`.

**Corrections to round 2 (both were my errors, not the earlier document's):**

| round-2 claim | corrected |
|---|---|
| `0x901b440` = "the teardown helper" | **`AppleJPEGDriver::checkDARTException()`** — it is the DART-exception handler, and it is what performs the 4-object release |
| `0x901cb58` = `showRequestInfo`, and "the fake-header pair is only logged there" | **`AppleJPEGCoreAnalyzer::submitAnalyticData()`**, and its `x19` is `[this+0x168]` (the analyser), **not the request** — so its `+0xe8`/`+0xf0` reads are the analyser's counters. The "req+0xe8/0xf0 is only logged" argument in round 2 was built on a mis-attribution; the corrected statement is in §6 |
| `0x901bc6c` = "a register-bank writer" | **`AppleJPEGCoreAnalyzer::checkFrameBufferFormat(uint32_t, uint32_t)`** — a fourcc switch; its base is `this + (w2==1 ? 0x198 : 0xa0)` |
| `0x901c7f8` — not previously identified | **`AppleJPEGCoreAnalyzer::~AppleJPEGCoreAnalyzer()`** — its `+0x2b8`/`+0x2c0` are the *analyser's* fields. This was a false positive on my first pass at the escalation and is recorded so it is not re-walked |

The full map is in `analysis/priv24A435/lpe27gm/symmap.txt`. It confirms round 2's selector map
independently (`startDecoder` `0x9018830`, `startEncoder` `0x9019ad0`, `startEncoderExt` `0x9019ee4`,
`startDecoderExt` `0x9019334`, `startEncoder2024` `0x901a9e8`, `startDecoder2024` `0x901a348`) and
gives the two hardware-setup functions their names: `RequestHandling::decodeHWRequestSetup`
(`0x903b6c8`) and `RequestHandling::encodeHWRequestSetup` (`0x903bcd8`).

---

## 2. The surface lifecycle: looked up, stored, released — never retained

`setupBuffersForCoding_gated` (`0x9017b78`) populates both surface fields:

```
; --- req+0x2c0 ---
0x9017bac  str  q0, [x24]                  ; x24 = req+0x2b8: clears +0x2b8 and +0x2c0
0x9017bb8  ldr  x21, [this, #0x148]        ; the IOSurfaceRoot provider
0x9017bbc  ldr  w23, [req, #0x2b0]         ; <<< the 32-bit surface ID, from client+0x08
0x9017bc0  bl   #0x903cac8                 ; -> x22 (the task argument)
0x9017bd0  mov  x2, x22
0x9017bd4  bl   #0x903c6e8                 ; IOSurfaceRoot lookup
0x9017bd8  str  x0, [req, #0x2c0]
0x9017be8  mov  w1, #0
0x9017bec  bl   #0x903c888                 ; <<< (surface, 0)  -- a LOCK, not a retain

; --- req+0x2b8 ---
0x9017e0c  ldr  x0, [this, #0x148]
0x9017e10  ldr  w1, [req, #0x2ac]          ; <<< the other surface ID, from client+0x00
0x9017e14  mov  x2, x22
0x9017e18  bl   #0x903c6e8
0x9017e1c  str  x0, [req, #0x2b8]
0x9017e28  mov  w1, #1
0x9017e2c  bl   #0x903c888                 ; <<< (surface, 1)  -- a LOCK, not a retain
```

`0x903c888` → `0xa35ea68`, whose body is:

```
0xa35ea68  pacibsp ; …
0xa35ea80  ldr  x0, [x0, #0x50]            ; obj+0x50
0xa35ea84  bl   #0xa3828bc                 ; a lock
0xa35ea88  ldrb w8, [x19, #0x3d0]          ; a flag
0xa35ea8c  tbz  w8, #5, #0xa35eab0
```

— a lock/unlock-style operation parameterised by the mode argument, **not `OSObject::retain`**
(a retain is a `lock; ldadd` on a refcount field with no mode argument). Round 2's and the earlier
document's description of `0x903c888` as "a RETAIN" is **wrong**; it is the counterpart of the
teardown's `0x903c898` unlock. There is exactly **one** pair of calls to it in the whole kext, and
both are in this function.

The teardown then releases what the lookup returned:

```
0x9018084  ldr  x0, [req, #0x2b8]
0x901809c  bl   #0x903c8c8                 ; unlock (0xa35cd34), conditional on req+0x2d8
0x90180a8  bl   #0x903c898                 ; unlock (0xa35eac8), conditional on req+0x2da
0x90180c0  ldr  x8, [x16, #0x28]!          ; vtable[0x28]
0x90180c8  blraa x8, x16                   ; <<< OSObject::release
0x90180cc  cbz  w21, #0x901810c            ;  <- and NOTHING clears req+0x2b8
...
0x90181a8  ldr  x0, [req, #0x2c0]
0x90181ec  blraa x8, x16                   ; <<< OSObject::release
0x90181f0  ...                             ;  <- and NOTHING clears req+0x2c0
```

**Net: the driver's reference is the lookup's `+1`, and the teardown drops it. The request never
held an independent reference, so after the teardown the field is a pointer to an object the driver
no longer owns.**

---

## 3. The two release points, and the window between them

Round 2 established the polarity; §1's symbol map only confirms it:

| path | gate | what happens |
|---|---|---|
| `queue_io_gated` (`0x9018c0c`) | `[req+0x10] == 0` **or** dispatch error | `checkDARTException` → **release now** |
| `finish_io_gated`, async arm (`0x9016aec`, from `interruptOccurred_gated`) | `[req+0x10] != 0` | `checkDARTException` → release, then `kfree_type(req)` |

`[req+0x10]` is `*(u64 *)(structureInput + 0x30)`, and nothing but the request constructor ever
writes it. So the client picks one of two behaviours for the whole life of the request.

**The `== 0` path is the dangerous one, and the order inside it is the whole bug:**

```
queue_io_gated:
  0x9018fd8  bl  #0x9017b78      ; setupBuffersForCoding_gated  -> req+0x2b8 / req+0x2c0 set
  0x901904c  bl  #0x903acd8      ; decodeRequestValidation
  0x9019160  bl  #0x903b6b4      ; decodeHWRequestSetup
  0x90191f8  bl  #0x9013228      ; enqueue
  0x901927c  bl  #0x9015c38      ; begin_io_gated  -- hardware started
  0x90191ac  cbz x23, #0x90191b4 ; x23 = [req+0x10] == 0  ->  TAKE THE TEARDOWN
  0x90191bc  bl  #0x901b440      ; checkDARTException  -- releases the surfaces
```

and inside `checkDARTException` (`0x901b440`):

```
0x901b480  bl  #0x9017fe4      ; <<< the 4-object release: req+0x2b8 and req+0x2c0 released
0x901b4e0  mov w24, #0x64
0x901b4f8  mov w0, #0xa
0x901b4fc  bl  #0x903c598      ; IOSleep(10)   × 100   ==  ~1 second
0x901b500  subs w24, w24, #1
0x901b504  b.ne #0x901b4e4
```

**The release is step 1 of the teardown; the ~1-second sleep is step 2.** So from the instant the
driver gives up its reference, there is a driver-inserted one-second interval before the ioctl even
returns — and then the completion can still be arbitrarily far away (it depends only on when the
hardware finishes and the interrupt is serviced).

---

## 4. The use, on the completion path

`interruptOccurred_gated` (`0x90166d0`) calls `finish_io_gated(this, req, 0, core, async = true)`
(`0x9016744`). The async arm runs the per-core release work and then:

```
0x9016dc4  ldr  w8, [req, #0x4f0]
0x9016dc8  cbz  w8, #0x9016de4
...
0x9016de4  ldr  w8, [req, #0x70]
0x9016de8  cbnz w8, #0x9016e0c          ; req+0x70 is 0 on this path (the sync arm never ran)
0x9016dfc  str  w8, [req, #0x70]
0x9016e00  ldr  x0, [this, #0x168]      ; the AppleJPEGCoreAnalyzer
0x9016e04  mov  x1, x19                 ; the request
0x9016e08  bl   #0x901c880              ; <<< collectCoreDataFromRequest(req)
0x9016e0c  ...
0x9016f70  ldr  x8, [req, #0x10]        ; the gate is only consulted AFTERWARDS
```

and `collectCoreDataFromRequest` (`0x901c880`):

```
0x901c880  … (x20 = req)
0x901c8a4  ldr  w8, [req, #0x2a8]       ; the encode/decode selector
0x901c8ac  mov  w8, #0x2b8
0x901c8b0  mov  w9, #0x2c0
0x901c8b4  csel x8, x9, x8, eq          ; decode -> 0x2c0, encode -> 0x2b8
0x901c8b8  ldr  x0, [req, x8]           ; <<< THE RELEASED SURFACE
0x901c8bc  bl   #0x903c958              ; IOSurface accessor (0xa35b670)
0x901c8c0  mov  x21, x0                 ; its return value …
0x901c8d4  bl   #0x901ba70              ; … is used
0x901c9ac  mov  x1, x21
0x901c9d0  b    #0x901bc6c              ; … as the key of a fourcc switch
```

So the value read out of the released object **steers a comparison**, and the object is additionally
handed to further `IOSurface` entry points (`0x903c8f8` → `0xa3584c8`). The dereference is a
`bl` to a *resolved* stub, i.e. a direct call into `com.apple.iokit.IOSurface` with a stale `x0` —
so the immediate primitive is "IOSurface code runs with a freed `this`", which reads that object's
fields and uses them; it is not an immediate vtable hijack (those would need a vtable load *from*
the object, which this call path does not do).

**Two more users of the same stale pointer exist and are flag-gated, so they are recorded but not
counted as the trigger:**

| function | site | gate |
|---|---|---|
| `AppleJPEGDriver::showRequestInfo` (`0x901aec4`) | `0x9015d94` in `begin_io_gated` | `[this+0xce] & 1` |
| `AppleJPEGDriver::dumpBitstream` (`0x901b0e4`) | `0x9016bf4` in `finish_io_gated` | `[this+0x88] & 1`, `[this+0x108] >= 0xb0000`, `[this+0xca] & 1` |

Both dereference `req+0x2b8`/`req+0x2c0` heavily (12 and 5 sites respectively) and both would be
*stronger* UAFs than `collectCoreDataFromRequest` — but the flags are driver configuration, not
client input, so they are hardening observations rather than a chain.

---

## 5. The chain, and the one link that is not closed

```
sandboxed app / attacker-controlled JPEG
 -> ImageIO -> XPC -> com.apple.ImageIOXPCService        [iokit-user-client-class = AppleJPEGDriverUserClient]
 -> IOServiceOpen("AppleJPEGDriver") -> IOConnectCallStructMethod(selector 5|6|7, in 3488|4096)
 -> the handler copies structureInput+0x30 -> req+0x10          [0x901a424 / 0x9019620]
 -> queue_io_gated: setupBuffersForCoding_gated                [0x9017b78]
       IOSurfaceRoot lookup -> req+0x2b8 / req+0x2c0           [0x9017bd8 / 0x9017e1c]
 -> begin_io_gated  (hardware started)                         [0x901927c]
 -> [req+0x10] == 0  ->  checkDARTException                    [0x90191bc]
       release req+0x2b8 and req+0x2c0   *** NOT CLEARED ***    [0x90180c8 / 0x90181ec]
       then IOSleep(10) x 100  ==  ~1 s                        [0x901b4fc]
 -> ioctl returns success; the client may now drop its own reference to the surface
 -> hardware completes -> interruptOccurred_gated -> finish_io_gated(async)
 -> collectCoreDataFromRequest(req)                            [0x9016e08 -> 0x901c880]
       ldr x0, [req, #0x2c0]  ->  IOSurface code with a stale this   *** UAF ***
```

**Links 1–7 are byte-exact and verified. Link 8 is the one that is inferred — but this round
narrowed it further, and the evidence now leans the *other* way:**

> **Does the surface's refcount reach zero in the window?**

Two sub-questions, and the second one now has evidence:

**(a) Does the driver hold a reference of its own?** **No — proven.** Every `IOSurface` entry point
the driver calls was enumerated (`sym.py` over the kext's 30 IOSurface stubs, then a full
call-site sweep). On the surface object itself the driver makes exactly four kinds of call:
the lookup (×2), `0x903c888` (×2, the lock), and the teardown's unlock (×4) + `OSObject::release`
(×2). **There is no retain anywhere.** So whatever reference the teardown drops is one the *lookup*
was supposed to have granted.

**(b) Does the lookup grant one?** **Evidence says probably not.** The lookup is
`0x903c6e8` → `0xa36cbb0`, which calls `0xa36c868`; and a scan of the whole
`0xa36c868 … 0xa36cc00` range finds **no `ldadd`/`ldadda`/`stadd`/`swp`/`cas` — i.e. no atomic
reference-count increment — on any path**, and the successful return at `0xa36c9d8` is a bare
`mov x0, x19 ; … ; retab` with no out-of-line call on the way out. The table walk itself is
`x19 = [provider+0xd0 + ID*8]` with the count at `provider+0xd8` and an ID re-check at
`[x19+0x10]` (`0xa36c8a8`–`0xa36c92c`), i.e. a plain indexed lookup out of `IOSurfaceRoot`'s
surface array.

If that reading holds, then **`checkDARTException`'s `OSObject::release` is an over-release**, and
the chain loses its race entirely: the teardown itself drops the count to zero and frees the
surface, while both the client's `IOSurfaceRef` and `req+0x2b8` still refer to it. That would make
this a **deterministic use-after-free**, on the *normal* path as well as the `== 0` one — a
slow refcount underflow that only bites when the count reaches zero, which is exactly the shape of
a bug that survives a shipping driver's test suite.

Two things keep (b) short of PROVEN, and they are the recommended next reads:

1. **A retain may be out-of-line.** The scan rules out an inline atomic increment; it does not rule
   out a `bl` to a `retain` helper. The candidates in range are `0xa382edc`, `0xa38301c`,
   `0xa38304c` (all called with a task/buffer, not the surface) — but that must be checked, not
   assumed.
2. **`0xa36cbb0` has a second half.** It calls `0xa36cc68` (a cache lookup) *before* the table walk
   and locks `x19+0xd8` on a cache hit; a reference could be granted on the cache path rather than
   the table path.

Either read settles the finding: **(b) false ⇒ a deterministic UAF; (b) true ⇒ a wide-window race.**
There is no third outcome, because (a) is settled.


---

## 6. What this changes about rounds 1 and 2

| prior claim | status after this round |
|---|---|
| §12: double `finish_io_gated` ⇒ double release of the `IOSurface` | **still REFUTED** — the two teardown triggers remain mutually exclusive (round 2 §4) |
| round 2: the caller-struct alias is a latent hazard with no consumer | **unchanged as a statement**, but it is *not* the escalation vehicle. The aliased pair `(req+0x4c8, req+0x4d0)` is copied to `(req+0xe8, req+0xf0)` by `decodeHWRequestSetup` (`0x903b808` / `0x903b818`) and has no dereferencing reader — §1's corrected symbol map removes the one candidate round 2 thought it had |
| round 2: the client-controlled leak is DoS | **unchanged** — and it is a *symptom of the same defect*: the `== 0` path both releases early and skips the free, so the request leaks with a stale surface pointer inside it |
| round 2: the client-forced early DMA teardown is mitigated by the ~1 s wait | **the same wait is what makes this chain practical** — it is a mitigation for the DMA and a gift to the attacker for the lifetime |
| "the driver releases 4 objects and clears 2" | **the important half is not the missing clear** — it is that one of the two uncleared fields is a pointer to an object whose reference was just dropped, and the object is used again 1 second later |

---

## 7. Honest status

**Proven (byte-exact, reproducible with `analysis/priv24A435/lpe27gm/`):**

1. `req+0x2b8` / `req+0x2c0` are set from an `IOSurfaceRoot` lookup and are **never retained**; the
   only other operation on them at setup is `0x903c888`, which is a lock, not a retain.
2. `checkDARTException` calls `OSObject::release` on both (`vtable[0x28]`) and **does not clear
   either field**.
3. `collectCoreDataFromRequest`, reached unconditionally on the async completion path *before* the
   gate is consulted, loads one of those two fields and calls into `com.apple.iokit.IOSurface`
   with it.
4. The trigger is `[req+0x10] == 0`, i.e. `*(u64 *)(structureInput + 0x30) == 0` — client data,
   written once and never modified.
5. Between the release and the use there is a driver-inserted ~1-second sleep.
6. `showRequestInfo` and `dumpBitstream` are two further users of the same stale pointer, gated on
   driver configuration flags.
7. The driver **never retains** the surface: every IOSurface call it makes on the object is
   enumerated and contains no retain.
8. The lookup path contains **no atomic reference-count increment** on any branch.

**Not proven:**

* that the lookup is borrowed rather than owned — which is the same as asking whether the teardown's
  release is an over-release (§5(b)). This is now a single, bounded read;
* that `ImageIOXPCService` can be driven to `structureInput+0x30 == 0`;
* any memory-safety consequence at runtime. **No LPE is demonstrated.**

**Classification: the driver releases a reference it never took, on a client-supplied object, and
then dereferences the pointer one second later on the completion path. If the lookup is borrowed
this is a deterministic over-release and a use-after-free; if it is owned, it is a wide-window
use-after-release race. The evidence available leans toward the former, and the deciding read is
one function.**

---

## 8. Artifacts

All under `analysis/priv24A435/lpe27gm/`.

| file | purpose |
|---|---|
| `symmap.py` / `symmap.txt` | **new**: recover a symbol map for a stripped kext from the `os_log` signature strings — 116 functions for `com.apple.driver.AppleJPEGDriver` |
| `jt.py` | kext access: `LC_FUNCTION_STARTS` boundaries, sections, direct arm64e pointer decode, `iter_insns`, `stub_target` |
| `dump.py` / `scan.py` / `sym.py` / `kref.py` | function dumps and caller lists; offset/pattern scans; stub→kext resolution; `__kalloc_type` site→object lifecycle map |
| `dis/*.txt` | full disassembly of `finish_io_gated`, `interruptOccurred_gated`, `queue_io_gated`, `checkDARTException`, the 4-object release, `setupBuffersForCoding_gated` |

New traps worth carrying forward:

* **`os_log` signature strings are a symbol table.** Check for `adrp+add` to a `__cstring` string
  containing `::` before concluding a kext is unnamed.
* **A lock is not a retain.** `0x903c888` looks like a retain by position (called on a freshly
  looked-up object) but takes a *mode* argument and locks `obj+0x50`. Read the callee before
  assuming a refcount.
* **An offset match is not an object match.** `+0x2b8` exists in both the request and the
  CoreAnalyzer; my first escalation attempt (`0x901c7f8`) was the analyser's destructor. Always
  confirm the base register's provenance from the caller, not from the offset.
