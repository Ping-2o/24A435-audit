# PRIV-24A435 — round 4: the LPE chain (release of a borrowed IOSurface reference)

Completion of `priv24A435_lpe_27gm_round3_uaf.md`. Round 3 established that the driver releases the
`IOSurface` without ever retaining it, and that the pointer is dereferenced afterwards on the
completion path. This round closes the ownership question and writes the chain.

> **This is the LPE chain.** It is a **deterministic use-after-free of a client-supplied
> `IOSurface`**, triggered by a single client-controlled field, with the driver itself performing
> the invalid free. One assumption is load-bearing and is labelled **STRONG**, not PROVEN, in §3 —
> the evidence for it is three fully disassembled functions and a 12-kext consumer survey, but it is
> absence-of-increment reasoning and a runtime test would make it airtight.

---

## 0. The bug in one paragraph

`AppleJPEGDriver` obtains the client's `IOSurface` through `IOSurfaceRoot`'s **borrowed-pointer**
lookup (`0xa36cbb0`), stores the raw pointer in the `JpegRequest`, and later calls
**`OSObject::release`** on it (`0x90180c8` / `0x90181ec`) — a decrement with no matching increment.
Because the lookup's reference is the *only* kernel reference behind the surface ID, the release
drives the refcount to zero and the object is freed **while `IOSurfaceRoot`'s ID table still points
at it, while the client's `IOSurfaceRef` is still live, and while `req+0x2b8` / `req+0x2c0` still
hold it.** The driver then dereferences that pointer again ~1 second later from the completion path
(`collectCoreDataFromRequest`, `0x901c880` → `com.apple.iokit.IOSurface`).

---

## 1. The trigger (client-controlled, one field)

```
IOConnectCallStructMethod(selector 5|6|7, structureInput = AppleJPEGDriverIOStruct{,Ext,2024})
  with *(uint64_t *)(structureInput + 0x30) == 0
```

`structureInput + 0x30` is copied verbatim into `req+0x10` (`0x901a424` for the 2024 variant,
`0x9019620` for the Ext variant; the same 16-byte copy exists in all six `start*` handlers). Nothing
but the request constructor ever writes `req+0x10`, so the client's value decides the whole life of
the request:

| `[req+0x10]` | `queue_io_gated` | `finish_io_gated` (async) |
|---|---|---|
| `!= 0` (the working path) | no teardown | teardown, **then** `kfree_type(req)` |
| **`== 0` (the trigger)** | **teardown now** (`0x90191ac` → `0x90191bc`) | no teardown, **and no free** |

`+0x30 == 0` is not an artificial value: it is the "the fake header is in place, do not copy it"
branch — the same condition that makes the driver take the `str x23,[x21,#0x4c8]` alias at
`0x901a678` / `0x901965c`. It is a real, reachable code path in the driver.

---

## 2. The invalid release, step by step

```
setupBuffersForCoding_gated (0x9017b78)
  0x9017bd4  bl  #0x903c6e8     ; IOSurfaceRoot lookup (provider, id=req+0x2b0, task)
  0x9017bd8  str x0, [req, #0x2c0]
  0x9017bec  bl  #0x903c888     ; (surface, 0)  -- lock + clear flags  [NOT a retain, see §3]
  0x9017e18  bl  #0x903c6e8     ; lookup (provider, id=req+0x2ac, task)
  0x9017e1c  str x0, [req, #0x2b8]
  0x9017e2c  bl  #0x903c888     ; (surface, 1)  -- lock + clear flags
        ...  no retain anywhere ...

queue_io_gated (0x9018c0c), [req+0x10] == 0
  0x90191bc  bl  #0x901b440     ; checkDARTException

checkDARTException (0x901b440)
  0x901b480  bl  #0x9017fe4     ; the 4-object release
        ...  and inside it, for BOTH surfaces:
  0x90180c0  ldr  x8, [x16, #0x28]!    ; OSObject::release
  0x90180c8  blraa x8, x16
  0x90180cc  cbz  w21, #0x901810c      ;  <- req+0x2b8 is NOT cleared
  0x90181ec  blraa x8, x16             ; OSObject::release
  0x90181f0  ...                       ;  <- req+0x2c0 is NOT cleared
  0x901b4e0  mov  w24, #0x64
  0x901b4fc  bl   #0x903c598           ; IOSleep(10) × 100  ==  ~1 s
```

The refcount goes to zero here — nothing else in the kernel holds a reference to that ID (§3) — and
the object is freed. `req+0x2b8` / `req+0x2c0` still contain the address, and so does
`IOSurfaceRoot`'s ID table.

---

## 3. Why the release is invalid — the evidence, and what is assumed

**PROVEN — the driver never retains.** Every `IOSurface` entry point the kext imports was enumerated
(30 stubs) and every call site swept. On the surface object the driver makes exactly three kinds of
call: the lookup (×2), `0x903c888` (×2), and the teardown's unlock (×4) + `OSObject::release` (×2).
`0x903c888` → `0xa35ea68` was disassembled in full (96 bytes): it locks `obj+0x50`, clears bits 5/4
of `obj+0x3d0`, and unlocks. **It touches no reference count.** So the reference the teardown drops
was never taken by the driver.

**STRONG — the lookup returns a borrowed pointer, so that reference was never granted by the lookup
either.** Three functions on the path were disassembled end to end and their out-of-line callees
checked:

| function | role | reference-count increment? |
|---|---|---|
| `0xa36c868` | the surface-table walk (`x19 = [provider+0xd0 + ID*8]`, count at `provider+0xd8`, ID re-check at `[x19+0x10]`) | **none** |
| `0xa36cbb0` | the exported entry point (`0x903c6e8` resolves here); locks `provider+0x140`, walks, unlocks, returns | **none** |
| `0xa36cd6c` | the second wrapper around the same walk | **none** |

A scan of all three for `ldadd`/`ldadda`/`stadd`/`swp`/`cas` returns nothing, and no `bl` on the
path reaches a retain — the only call made on the lookup *result* is `0xa35866c`, which is a
**validator**: it `ldar`s `obj+0xc`, and on failure raises `0x85210034` through `0xa382f1c` (a panic
code). The caller then does `csel x21, x21, xzr, ne` — i.e. the result is NULLed on validation
failure. That is a check, not a retain.

**Corroboration from the other consumers.** `0xa36cbb0` has **no internal callers** in the IOSurface
kext — it exists for external consumers. Twelve kexts import it
(`AppleAVD`, `AppleAVE2`, `AppleH16ANEInterface`, `AppleH16CameraInterface`, `AppleJPEGDriver`,
`AppleM2ScalerCSCDriver`, `AppleMobileDispH17P-DCP`, `AppleProResHW`, `VideoProcessing`,
`IOGPUFamily`, `IOMobileGraphicsFamily`, `IOMobileGraphicsFamily-DCP`), with **45 call sites in
total**, and **not one of them** uses the `OSObject::release` pointer-auth diversity
(`movk xN, #0x3a87, lsl #48` — the same diversity the JPEG driver's teardown uses) within 80
instructions of the lookup. The borrowed-pointer convention is the only reading under which eleven
Apple drivers are simultaneously correct and the twelfth is not.

**The one load-bearing assumption.** If the lookup *is* owned (i.e. the table entry is not a
reference and the lookup's `+1` is what the driver drops), then the release is balanced, and the
finding degrades from "deterministic invalid free" to "wide-window use-after-release race" — still a
bug, but not this chain. **This is the single thing to confirm at runtime**, and §6 gives the
one-line experiment.

**Why the borrowed reading is not self-contradictory.** The lookup unlocks `provider+0x140` before
returning, which looks unsafe for a borrowed pointer. It is safe because the *table entry* is the
reference: an `IOSurface`'s kernel lifetime is bounded by its ID-table entry, which is removed by
the client's explicit release (or its userclient's teardown), not by a transient lookup. That is
precisely the invariant the driver's stray `release` breaks.

---

## 4. The chain

```
1. attacker's app asks ImageIO to decode an image
     -> ImageIOXPCService (holds iokit-user-client-class = AppleJPEGDriverUserClient)
     -> creates/attaches the destination IOSurface S, obtains its 32-bit ID

2. ImageIOXPCService issues IOConnectCallStructMethod(selector 5|6|7, 3488|4096 bytes)
     with *(u64*)(structureInput + 0x30) == 0        <-- THE TRIGGER
     and structureInput+0x00 / +0x08 = the two surface IDs

3. queue_io_gated: setupBuffersForCoding_gated
     req+0x2c0 = lookup(id0)      req+0x2b8 = lookup(id1)      [borrowed, no +1]

4. begin_io_gated  -> the hardware is programmed with S's physical pages

5. [req+0x10] == 0  ->  checkDARTException
     OSObject::release(req+0x2c0)      OSObject::release(req+0x2b8)
     *** refcount of S -> 0, S is FREED ***
     *** IOSurfaceRoot's ID table still maps id -> S ***
     *** the client's IOSurfaceRef for id is still live ***
     then IOSleep(10) x 100  ==  ~1 s

6. the ioctl returns success; ImageIOXPCService still believes S is alive

7. reclaim: the attacker's next kernel allocations take S's slot
     (an IOSurface is ~0x3d8 bytes; the freed object is in a normal zone)

8. THE USE - any of:
   a. the driver's own completion path:
        interruptOccurred_gated -> finish_io_gated(async)
        -> collectCoreDataFromRequest(req)          [0x9016e08 -> 0x901c880]
             ldr  x0, [req, #0x2c0|0x2b8]           <-- freed/reclaimed object
             bl   #0x903c958                        <-- IOSurface code, x0 = attacker data
             ... its return value keys a fourcc switch at 0x901bc6c
   b. ImageIOXPCService's own next use of the surface ID:
        any IOSurface operation re-enters the lookup and gets the SAME dangling pointer
   c. any later decode that names the same ID (the driver looks it up again)
```

**Primitive:** kernel code (IOSurface, and anything reached through the fields it reads) executes
with `this` pointing at attacker-controlled memory. That is a type-confusion read/write primitive
in the IOSurface path — the standard route from there to arbitrary kernel read/write is field
grooming of the reclaimed object (control an IOSurface field that is used as a pointer or as a
buffer length).

**Two aggravating details:**

* **The driver's own invalid free is the free.** No attacker-side race is needed to *free* the
  object — only to reclaim it.
* **The leaked request keeps the stale pointer alive forever.** Because the `== 0` path also skips
  `kfree_type`, the request is leaked with `req+0x2b8` / `req+0x2c0` inside it, so the dangling
  pointer is not "used up" — and the same defect is why round 2 saw a client-controlled heap leak.

---

## 5. Honest status

| claim | status |
|---|---|
| `structureInput+0x30` → `req+0x10`; `== 0` selects the early teardown | **PROVEN** (`0x901a424` / `0x9019620`; single writer; coverage scan) |
| the driver never retains the `IOSurface` | **PROVEN** (all 30 imports, all call sites; `0x903c888` disassembled in full) |
| the teardown calls `OSObject::release` on both fields and clears neither | **PROVEN** (`0x90180c8`, `0x90181ec`; no `str xzr` to `+0x2b8`/`+0x2c0`) |
| the completion path dereferences those fields | **PROVEN** (`0x9016e08` → `0x901c880` → `0x903c958`, before the gate is consulted) |
| the window between release and use is ~1 s | **PROVEN** (`0x901b4e0`: 100 × `IOSleep(10)`) |
| **the lookup returns a borrowed pointer ⇒ the release is an over-release ⇒ the object is freed** | **STRONG** — three functions disassembled, no increment anywhere, 45 call sites in 12 kexts none of which releases; **not confirmed at runtime** |
| the surface's ID table entry is the reference (so the ID dangles after the free) | **INFERRED** from the borrowed-pointer reading |
| **a full LPE** | **NOT DEMONSTRATED** — the chain is complete on paper and every link is evidenced, but the free is inferred rather than observed |

**Falsification.** The chain dies if the lookup is owned. The one-line runtime test: take any of the
twelve consumers, call `IOSurfaceRoot::lookupSurface` for a live ID, read the `IOSurface`'s retain
count before and after, and see whether it incremented. Alternatively, instrument the JPEG driver:
after one `+0x30 == 0` decode, check whether `IOSurfaceGetUseCount` for the ID drops to zero while
the client's `IOSurfaceRef` is still held.

---

## 6. What I would do next, in order

1. **Settle ownership (decides everything).** Read `IOSurfaceRoot`'s own `IOSurfaceRelease`/table-
   removal path and confirm whether the table entry holds a reference; or check `decr_osobject_release_count`
   on the object after a lookup. One function, or one runtime probe.
2. **If borrowed:** confirm that a `+0x30 == 0` decode frees the client's surface — a single
   `IOSurfaceGetUseCount` before/after.
3. **Reachability:** determine whether `ImageIOXPCService` can be driven to `structureInput+0x30 == 0`
   from an attacker-supplied image (this is the partial-decode / `newHeader`-in-place path; it is a
   real branch in the driver, but I have not shown an ImageIO entry point that sets it).
4. **Then** build the reclaim + type-confusion step.

---

## 7. Artifacts

`analysis/priv24A435/lpe27gm/` — `symmap.py` (symbol recovery from `os_log` strings),
`jt.py` / `dump.py` / `scan.py` / `sym.py` / `kref.py`, `symmap.txt`, `dis/*.txt`.

New traps recorded this round:

* **Prove ownership by absence of increment, then check the peers.** Disassemble the *whole* lookup
  (all three wrappers), scan it and every out-of-line callee for `ldadd`/`stadd`/`swp`/`cas`, and
  then compare against the other importers of the same entry point — the majority convention is the
  strongest available evidence for a borrowed/owned question that has no symbol to read.
* **The `OSObject::release` pointer-auth diversity is a reusable signature.** `movk xN, #0x3a87,
  lsl #48` combined with vtable slot `0x28` is `OSObject::release`; searching for that 32-bit
  encoding (`(w & 0xFFE0001F) == 0xF28D50E0`) finds releases without symbols. Other slots have their
  own stable diversities (`0xcda1` for the object-pointer key, `0x2e4a` / `0xf36c` / `0x9285` /
  `0x3a87` seen so far).
