# PRIV-24A435 audit

> Static reverse-engineering audit of the iOS 27 kernel and privileged media stack, centered on **iOS 27.0 GM (24A435, iPhone17,5)** with selected cross-version validation against **24A437** and **27.2 beta 1 (24B5084k)**.

> [!IMPORTANT]
> This repository contains AI-assisted security research.
> Every claim is intended to be independently reproducible from the supplied binaries, addresses, disassembly and scripts.

## Current finding

### AppleJPEGDriver — IOSurface use-after-release

A client-controlled request path can trigger early teardown after the JPEG hardware has already been started.

`AppleJPEGDriver`:

1. looks up and retains the client's `IOSurface`;
2. stores the pointers in the request;
3. starts the hardware and records the pending request;
4. releases its surface references during early teardown;
5. **does not clear the stored pointers**;
6. later dispatches the same request from the hardware interrupt;
7. dereferences the released surface pointer from the completion path.

Simplified chain:

```text
userspace
  ↓
AppleJPEGDriverUserClient
  ↓
structureInput + 0x30 == 0
  ↓
queue_io_gated
  ↓
hardware started
  ↓
early teardown
  ↓
OSObject::release(IOSurface)
  ↓
pointer remains in JpegRequest
  ↓
hardware interrupt
  ↓
finish_io_gated
  ↓
collectCoreDataFromRequest
  ↓
load stale IOSurface *
  ↓
read [surface + 0x80]
```

The stale-pointer dereference occurs **before** the completion path checks the request gate.

## Status

**Proven at the binary level:**

* client-controlled early-teardown trigger;
* IOSurface lookup retains the object;
* teardown performs the matching release;
* request fields containing the surface pointers are not cleared;
* the pending hardware request survives teardown;
* completion later reloads the stale pointer;
* the pointer is dereferenced at `surface + 0x80`.

This establishes a **use-after-release / lifetime violation**.

If the client's remaining surface reference disappears during the window, the stale access becomes a true **use-after-free read**.

## Exploitability

Current primitive:

```text
released IOSurface *
        ↓
read [object + 0x80]
```

No reachable write primitive was found.

The main escalation candidates were investigated and closed:

* stores through the stale IOSurface pointer — **none found**;
* client-controlled OOB mapping — **kernel length validation prevents it**;
* DMA into memory after unmap — **completion synchronization closes the window**;
* second release of `req+0x488` — **latent, but no reachable second completion established**.

**No LPE, kernel R/W, or control-flow hijack is claimed.**

## Other work

The repository also documents the earlier `_dmaReferences` investigation and the reconstruction of the path:

```text
AppleJPEGDriver
 → IOSurface
 → IOBufferMemoryDescriptor
 → IODMACommand
 → dmaCommandOperation
 → _dmaReferences
```

Several initially promising lifetime and refcount hypotheses were subsequently refuted. They are kept in the repository to preserve the audit trail.

## Scope

Techniques used include ARM64E disassembly, authenticated vtable-call recovery, object-lifetime reconstruction, whole-kext load/store scans, call-graph analysis, cross-kext reference-count analysis, and cross-version binary comparison.

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
