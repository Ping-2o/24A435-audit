# PRIV-24A435 audit

> Static reverse-engineering audit of the iOS 27 kernel and privileged media stack, centered on **iOS 27.0 GM (24A435, iPhone17,5)** with selected cross-version validation against **24A437** and **27.2 beta 1 (24B5084k)**.

> [!IMPORTANT]
> This repository contains AI-assisted security research.
> Every claim is intended to be independently reproducible from the supplied binaries, addresses, disassembly and scripts.

## Current headline

The strongest result in this repository is now an **AppleJPEGDriver / IOSurface lifetime bug chain**.

A client-controlled request field can select an early teardown path after the JPEG hardware has already been started. On that path, `AppleJPEGDriver` releases two `IOSurface` objects stored in the request, does not clear the stored pointers, waits for approximately one second, and later dereferences one of those same pointers from the asynchronous completion path.

The driver itself contains **no matching retain** of either surface.

Static analysis of the relevant `IOSurfaceRoot` lookup path likewise found no reference-count increment, and a survey of **45 lookup call sites across 12 importing kexts** found no peer consumer performing the corresponding `OSObject::release`.

This strongly suggests that the lookup returns a **borrowed pointer**.

If that ownership interpretation is correct, the JPEG teardown performs an **over-release of a client-supplied IOSurface**, potentially freeing it while the client's surface reference, the IOSurface ID table, and the driver's request still refer to the object.

The driver then uses the stored pointer again from its completion path.

**That would be a deterministic kernel use-after-free.**

However:

> **A full LPE has not been demonstrated.**
>
> The load-bearing ownership assumption has strong static evidence but has not yet been confirmed at runtime. No end-to-end reclaim or privilege-escalation exploit is provided.

---

## AppleJPEGDriver chain

The relevant request path is:

```text
userspace / ImageIO path
        |
        v
AppleJPEGDriverUserClient
        |
        | IOConnectCallStructMethod(...)
        v
start* handler
        |
        | structureInput + 0x30
        v
JpegRequest + 0x10
        |
        v
queue_io_gated
        |
        +--> setupBuffersForCoding_gated
        |       |
        |       +--> IOSurfaceRoot lookup(id0)
        |       |       -> req + 0x2c0
        |       |
        |       +--> IOSurfaceRoot lookup(id1)
        |               -> req + 0x2b8
        |
        +--> hardware setup
        |
        +--> begin_io_gated
        |
        | if [req + 0x10] == 0
        v
checkDARTException
        |
        +--> OSObject::release(req + 0x2b8)
        +--> OSObject::release(req + 0x2c0)
        |
        | pointers are NOT cleared
        |
        +--> IOSleep(10) x 100
                ~1 second
        |
        v
hardware completion
        |
        v
finish_io_gated(async)
        |
        v
collectCoreDataFromRequest
        |
        +--> load req + 0x2b8 / 0x2c0
        |
        v
IOSurface code receives the stored pointer again
```

The trigger is a single client-controlled field:

```c
*(uint64_t *)(structureInput + 0x30) == 0
```

That value is copied into `JpegRequest + 0x10` and determines whether teardown occurs immediately in `queue_io_gated` or later during normal completion.

---

## What is proven

### Client-controlled teardown gate

`structureInput + 0x30` is copied directly into `req + 0x10`.

The request constructor is the only writer found for this field.

Therefore the client controls which lifetime path the request takes.

### The surfaces are looked up and stored

`setupBuffersForCoding_gated` performs two `IOSurfaceRoot` lookups and stores their results at:

```text
req + 0x2b8
req + 0x2c0
```

### AppleJPEGDriver does not retain them

Every IOSurface entry point imported by the kext was enumerated and its call sites inspected.

The operation previously suspected to be a retain (`0x903c888`) was disassembled and is instead a lock/flag operation.

No independent surface retain was found anywhere in the driver.

### The teardown releases both surfaces

`checkDARTException` reaches the common teardown routine, which performs:

```text
OSObject::release(req + 0x2b8)
OSObject::release(req + 0x2c0)
```

Neither request field is cleared afterwards.

### The pointers are used later

The asynchronous completion path reaches:

```text
finish_io_gated
    -> AppleJPEGCoreAnalyzer::collectCoreDataFromRequest
```

which loads one of those same request fields and passes it into IOSurface code.

This happens before the request gate is consulted.

### The release/use window is unusually large

The teardown contains:

```text
100 x IOSleep(10)
```

giving approximately a **one-second interval** between the early release and later completion processing.

---

## The remaining ownership question

The central unresolved question is:

> Does `IOSurfaceRoot`'s lookup return an owned (`+1`) reference or a borrowed pointer?

The current static evidence favors **borrowed**.

Three relevant lookup functions were disassembled end-to-end.

No atomic reference-count increment was found.

No out-of-line retain on the returned object was identified.

The successful lookup behaves like a table walk returning the object stored for the surface ID.

As an independent cross-check, the same exported lookup was surveyed across its other consumers:

```text
12 importing kexts
45 call sites
```

None showed the `OSObject::release` pattern used by AppleJPEGDriver near the lookup.

That makes the JPEG driver's ownership behavior anomalous.

### Why this matters

If the lookup is **owned**:

```text
lookup +1
release -1
```

the early release is balanced, leaving a large use-after-release window whose exploitability depends on another reference disappearing.

If the lookup is **borrowed**:

```text
lookup +0
release -1
```

the driver releases a reference it never owned.

Under the reconstructed IOSurface lifetime model, that can free the object while its ID and other stale references remain live.

That changes the chain into a deterministic over-release / UAF candidate.

### Status

| Claim                                             | Status                    |
| ------------------------------------------------- | ------------------------- |
| Client controls `req+0x10`                        | **PROVEN**                |
| `== 0` selects early teardown                     | **PROVEN**                |
| Driver does not independently retain the surfaces | **PROVEN**                |
| Teardown calls `OSObject::release`                | **PROVEN**                |
| Released pointers remain stored                   | **PROVEN**                |
| Completion path dereferences them                 | **PROVEN**                |
| Release → use window is ~1 s                      | **PROVEN**                |
| IOSurface lookup is borrowed                      | **STRONG**                |
| Early release actually frees the IOSurface        | **NOT RUNTIME-CONFIRMED** |
| Attacker-controlled reclaim/type confusion        | **NOT DEMONSTRATED**      |
| Full LPE                                          | **NOT DEMONSTRATED**      |

---

## Why the earlier rounds still matter

The JPEG lifetime work came out of a broader audit of the 24A435 kernel.

### `_dmaReferences`

The original investigation found a suspicious 16-bit DMA reference counter in `IOMemoryDescriptor`.

The checked increment performs the equivalent of:

```text
atomic increment
    -> signed interpretation of old 16-bit value
    -> compare against 0x4000
```

while another descriptor family reaches an unbounded increment implementation.

Later work established that the AppleJPEGDriver DMA chain uses an `IOBufferMemoryDescriptor`, i.e. the descriptor family whose relevant op-5 path reaches the unbounded increment.

The chain was traced through:

```text
AppleJPEGDriver
 -> IOSurface
 -> IOBufferMemoryDescriptor
 -> IODMACommand
 -> dmaCommandOperation(op 5)
 -> _dmaReferences increment
```

This remains a real and byte-verified lifetime/refcount anomaly.

What has **not** been demonstrated is a practical way to drive the counter into a memory-corrupting state.

---

## Research progression

| Round              | Main result                                                                                                                                                            |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DMA/refcount audit | Identified `_dmaReferences`, its checked and unchecked increment families, consumer, and asymmetric lifetime behavior                                                  |
| JPEG reachability  | Closed the client → AppleJPEGDriver → IOSurface → DMA increment chain                                                                                                  |
| LPE round 2        | Reconstructed `JpegRequest` lifetime; refuted the earlier double-finish and caller-struct UAF hypotheses; found client-controlled premature teardown and request leak  |
| LPE round 3        | Found a real post-release consumer: the completion path dereferences the released IOSurface pointer                                                                    |
| **LPE round 4**    | Traced IOSurface lookup ownership; evidence strongly favors borrowed semantics, turning the early release into a deterministic over-release/UAF candidate if confirmed |

An important part of this repository is documenting **refuted hypotheses as well as surviving ones**. Several initially promising candidates disappeared after reconstructing complete object lifetimes.

---

## Earlier candidates that were closed

### Double `finish_io_gated`

Earlier work considered whether the request could reach teardown twice and therefore double-release its IOSurface.

Full lifecycle reconstruction showed that the relevant teardown conditions use opposite polarity on the same immutable request field.

**Status: REFUTED.**

### Caller-struct alias

The JPEG request contains a client-influenced alias path that initially looked capable of producing a stale-pointer consumer.

Recovered function identities and reader analysis showed no useful dereferencing consumer.

**Status: REFUTED as the escalation vehicle.**

### Stale DMA command slot

A possible stale-command/double-release path was investigated.

The relevant slots are reset before reuse.

**Status: REFUTED.**

Keeping these failures documented is intentional: they constrain the remaining attack surface and make the surviving chain considerably more meaningful.

---

## What would settle the current finding

The highest-value next experiment is very small.

Determine whether:

```text
IOSurfaceRoot::lookupSurface(live_id)
```

increments the IOSurface retain count.

A runtime retain-count observation or direct instrumentation of the lookup/release path would settle the ownership question.

If the lookup is confirmed borrowed, the next useful test is simply whether one request with:

```text
structureInput + 0x30 == 0
```

causes the client's still-live surface to be destroyed or otherwise leaves the ID table referring to a dead object.

Only after that result would reclaim/grooming work be justified.

---

## Scope and methodology

The project is primarily a static binary audit.

Techniques used across the rounds include:

* ARM64E chained-pointer decoding
* kext VA attribution
* `LC_FUNCTION_STARTS` recovery
* typed `kalloc_type` / `kfree_type` lifecycle reconstruction
* `os_log` string-based symbol recovery
* authenticated vtable-call identification
* cross-kext importer/call-site surveys
* reference-count operation searches
* selector and `IOCommandGate` reconstruction
* shared-cache instruction-pattern sweeps
* cross-version binary comparison

The goal is not to turn every suspicious instruction sequence into a vulnerability claim.

The standard used here is:

```text
candidate
    -> reachability
    -> ownership/lifetime
    -> consumer
    -> consequence
    -> runtime confirmation
```

Claims are downgraded or removed when a later round disproves an earlier assumption.

---

## Repository status

The current result is best summarized as:

> **A client-controlled AppleJPEGDriver path releases a client-supplied IOSurface that the driver never independently retained, leaves the pointer stored, waits approximately one second, and later dereferences it from the completion path. Static analysis strongly indicates that the IOSurface lookup itself is borrowed, which would make the release an over-release and the later access a deterministic UAF. The ownership interpretation has not yet been confirmed at runtime, and no end-to-end LPE is claimed.**

That is currently the strongest finding in the audit.

---

## Responsible research

This repository contains vulnerability research and reverse-engineering notes.

It intentionally distinguishes:

* **PROVEN** — established directly from the analyzed binaries;
* **STRONG** — supported by multiple independent static observations but missing a decisive confirmation;
* **INFERRED** — follows from another unresolved assumption;
* **NOT DEMONSTRATED** — plausible consequence for which no end-to-end evidence exists;
* **REFUTED** — investigated and contradicted by later analysis.

Corrections and independent reproduction are welcome.

---

> [!NOTE]
>
> ### Disclaimer
>
> This repository documents static security research and reverse engineering.
>
> No exploit is provided or claimed.
>
> A static path, suspicious lifetime transition, or theoretically reachable wrap is not treated as
> proof of exploitation. Findings should be independently reproduced before being relied upon.
>
> Educational and defensive research only.
