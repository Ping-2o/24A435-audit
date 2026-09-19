# PRIV-24A435 audit

> [!IMPORTANT]
> This repository contains AI-assisted security research.
> Every claim is intended to be independently reproducible from the supplied binaries, addresses, disassembly and scripts.

Static reverse-engineering audit of **iOS 27.0 GM 24A435 (iPhone17,5)**, with cross-build validation against later iOS 27 builds.

The main investigation follows an `IOMemoryDescriptor::_dmaReferences` hardening change through XNU, `IODMACommand`, IOSurface, AppleJPEGDriver and the real userspace JPEG client.

## Current result

The original reachability question is now closed:

```text
sandboxed app / JPEG input
        ↓
ImageIO
        ↓
com.apple.ImageIOXPCService
        ↓
JPEGH1.videodecoder
        ↓
AppleJPEGDriverUserClient
        ↓ selector 7
IOCommandGate::runAction(queue_io_gated)
        ↓
AppleJPEGDart::mapMemoryDescriptor
        ↓
IOSurface
        ↓
IOBufferMemoryDescriptor
        ↓
IODMACommand::prepare
        ↓
dmaCommandOperation(op 5)
        ↓
_dmaReferences++
        NO BOUND
```

The descriptor used by the JPEG DMA path is an IOSurface-owned
**`IOBufferMemoryDescriptor`**.

That matters because the two descriptor families behave differently:

| descriptor family              | operation | `_dmaReferences` behavior              |
| ------------------------------ | --------- | -------------------------------------- |
| `IOGeneralMemoryDescriptor`    | op 3      | bounded increment added in iOS 27.0 GM |
| **`IOBufferMemoryDescriptor`** | **op 5**  | **unbounded 16-bit atomic increment**  |

The JPEG path uses the second one.

The op-3 overflow hardening Apple added in 27.0 GM is therefore **not on the JPEG path**.

---

## What is proven

### 1. JPEG reaches the unbounded implementation

The previously unresolved ARM64E `__auth_got` entry was an analysis error.

For `DYLD_CHAINED_PTR_ARM64E_KERNEL`:

```text
bit 63 = auth
bit 62 = bind
```

The slot decodes as an authenticated rebase to:

```text
0xfffffff00a35b584
```

inside `com.apple.iokit.IOSurface`.

The target is effectively:

```asm
ldr x0, [x0, #0x30]
ret
```

and supplies the descriptor later passed to
`AppleJPEGDart::mapMemoryDescriptor`.

IOSurface's descriptor factories allocate from the
**`IOBufferMemoryDescriptor` metaclass**; the IOSurface binary contains no
`IOGeneralMemoryDescriptor` reference.

---

### 2. `IOBufferMemoryDescriptor` has no `_dmaReferences` ceiling

Its `dmaCommandOperation` implementation is:

```text
0xfffffff00b3406a4
```

For this implementation:

```text
op 3 → unsupported
op 5 → retain helper
```

The op-5 path reaches:

```asm
add    x8, x0, #0x34
mov    w9, #1
ldaddh w9, w8, [x8]
```

at:

```text
0xfffffff00b3409dc
```

There is:

```text
no sxth
no cmp
no upper bound
no overflow panic
```

The 16-bit counter can therefore increment through:

```text
0x4000
0x8000
0xffff
0x0000
```

at the machine-code level.

---

### 3. The hardened op-3 path is skipped

`IODMACommand::setMemoryDescriptor` issues the op-3 pin only when:

```text
fMapper == 0
```

The AppleJPEG command is created mapped with an `IODARTMapper`, therefore:

```text
fMapper != 0
```

and the op-3 call is skipped.

The later prepare path instead reaches the kernel's op-5 issuer:

```text
prepare
  → IODMACommand slot 0xa0
  → descriptor->dmaCommandOperation(op 5)
  → IOBufferMemoryDescriptor
  → retain helper
  → _dmaReferences++
```

So the distinction is stronger than the original:

> It is not merely “one atomic increment lacks the new bound.”

It is:

> **one descriptor family received the bound; the descriptor family used by the JPEG path did not.**

---

## Full 24A435 chain

```text
JPEG input
  ↓
ImageIO
  ↓
com.apple.ImageIOXPCService
  ↓
JPEGH1.videodecoder
  ↓
IOServiceMatching("AppleJPEGDriver")
  ↓
IOServiceOpen
  ↓
IOConnectCallStructMethod(selector 7, 3488-byte request)
  ↓
AppleJPEGDriverUserClient
  ↓
IOCommandGate::runAction(queue_io_gated)
  ↓
setupBuffersForCoding_gated
  ↓
AppleJPEGDart::mapMemoryDescriptor
  ↓
[IOSurface + 0x30]
  ↓
IOBufferMemoryDescriptor
  ↓
IODMACommand::withSpecification(kMapped)
  ↓
IODMACommand::setMemoryDescriptor
      op 3 → SKIPPED
  ↓
IODMACommand::prepare
  ↓
dmaCommandOperation(op 5)
  ↓
IOBufferMemoryDescriptor retain helper
  ↓
ldaddh [descriptor + 0x34]
  ↓
UNBOUNDED _dmaReferences++
```

Every link in this static chain is now backed by binary evidence.

---

# `_dmaReferences`: what it actually means

A complete sweep of the relevant readers changes the severity interpretation.

`_dmaReferences` behaves primarily as a **diagnostic/invariant counter**, not as an ownership
reference that directly decides whether the descriptor may be freed.

The important consumers fall into three groups:

| behavior                    | result                                   |
| --------------------------- | ---------------------------------------- |
| reporting sites             | log / telemetry                          |
| decrement while zero        | `vpanic` — `_dmaReferences underflow`    |
| `complete()` while non-zero | `vpanic` — `complete() while dma active` |

There is no discovered:

```text
if (_dmaReferences != 0)
    refuse_to_free();
```

ownership decision.

This removes several cheap UAF interpretations from the original investigation.

---

## The wrap hypothesis

Normal operation is balanced:

```text
prepare  → op 5 → ++
complete → op 6 → --
```

The op-5 increment is issued **once per command**, not once per DMA segment.

The earlier hypothesis that a fragmented surface could produce thousands of increments during
one decode was tested and **refuted**.

A counter wrap therefore requires net imbalance.

For the known leak shape, obtaining zero while a genuine DMA mapping is outstanding would require
approximately:

```text
65,535 leaked prepares
on the same persistent IOSurface descriptor

        +

1 genuine prepare
        ↓
counter wraps to zero

        +

completion while that mapping is live
```

No path capable of reliably producing this sequence has been demonstrated.

Therefore:

**the `_dmaReferences` wrap is a hardening defect, not a demonstrated UAF.**

---

# New AppleJPEG DMA teardown lead

The same investigation exposed a separate and substantially cheaper candidate in
AppleJPEGDriver's own DMA bookkeeping.

`JpegRequest` contains descriptor/command pairs such as:

```text
descriptor  +0x2c8
command     +0x300

descriptor  +0x2d0
command     +0x308
```

`AppleJPEGDart::mapMemoryDescriptor` writes the command output slot **only after successful
mapping**.

A failed map therefore leaves the old value in the command slot.

The teardown later:

1. reads the descriptor;
2. reads the command slot;
3. calls `unmapMemoryDescriptor`;
4. clears the **descriptor**;
5. does **not** clear the command slot.

This creates the following candidate state:

```text
descriptor = new/non-null
command    = stale pointer to already released IODMACommand
```

If the request object is reused and a subsequent map fails or is skipped before overwriting that
slot, teardown can pass the stale command back into:

```text
AppleJPEGDart::unmapMemoryDescriptor
```

---

## Why this is interesting

`unmapMemoryDescriptor` does not merely decrement some harmless reference.

It immediately uses the supplied command as an object:

```asm
ldr   x16, [x19]          ; load IODMACommand vtable
autda x16, x17
ldr   x8, [x16, #0x90]
blraa x8, x16             ; indirect virtual call
```

So the stale-pointer scenario is genuinely **UAF-shaped**:

```text
released IODMACommand
        ↓
stale command slot
        ↓
unmapMemoryDescriptor
        ↓
vtable load from freed object
        ↓
authenticated indirect call
```

Pointer authentication makes straightforward control-flow exploitation unlikely; recycled memory
would commonly be expected to fault rather than provide an immediately useful call target.

But this is still materially different from a benign double `release()`.

---

## What remains open for the double-release lead

Three links still decide whether it is a real reachable bug:

1. **Request reuse**

   It has not yet been proven that a `JpegRequest` carrying the stale command slot is reused for a
   subsequent job.

2. **Failure window**

   A path must exist where the new descriptor has already been installed but the corresponding
   `mapMemoryDescriptor` either fails or is skipped, leaving the stale command untouched.

3. **User-controlled reachability**

   It has not yet been demonstrated that the required state transition can be triggered through
   attacker-controlled userclient input.

Until those are closed:

> **This is a concrete double-release/UAF-shaped lead, not a demonstrated UAF.**

---

# Other findings

## MV-HEVC signed index

`CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb` contains the strongest surviving instance
of the signed-index class examined during the audit:

```text
64-entry array
+
signed-only upper-bound check
+
negative index accepted
+
sign-extended pointer-table index
+
pointer returned
```

The full-corpus sweep found no second equivalent instance.

Reachability and practical memory corruption remain separate questions.

---

## AVE2 signed-product loop

Another candidate uses a loop bound derived from:

```text
signed byte × signed byte
```

without an established relationship to the destination array length.

Cross-build investigation did not establish that later AVE2 changes were a security fix.

It remains a candidate, not a proven primitive.

---

# Cross-build status

The `_dmaReferences` implementation was compared against later iOS 27 binaries.

The relevant guard and atomic operations survive into **27.2 beta 1 (24B5084k)**.

In particular, the later build still contains:

```text
4 relevant atomic sites
1 bounded
3 unbounded
```

with the same functional roles.

The `IOBufferMemoryDescriptor` retain path remains unbounded.

So the issue is not merely a 24A435 GM artifact.

---

# Current verdict

| claim                                            | status                |
| ------------------------------------------------ | --------------------- |
| JPEG client → AppleJPEGDriver chain              | **PROVEN statically** |
| JPEG reaches `IODMACommand`                      | **PROVEN**            |
| descriptor comes from IOSurface                  | **PROVEN**            |
| descriptor family is `IOBufferMemoryDescriptor`  | **PROVEN**            |
| JPEG reaches unbounded op-5 `_dmaReferences++`   | **PROVEN**            |
| hardened op-3 protects the JPEG path             | **REFUTED**           |
| op-5 occurs once per segment                     | **REFUTED**           |
| prepare/complete normally balance the counter    | **PROVEN**            |
| `_dmaReferences` can wrap mathematically         | **PROVEN**            |
| practical 65,535-net-increment drive             | **NOT DEMONSTRATED**  |
| `_dmaReferences` UAF                             | **NOT PROVEN**        |
| AppleJPEG stale-command / double-release shape   | **FOUND**             |
| stale command is dereferenced through its vtable | **PROVEN**            |
| request reuse + required map failure sequence    | **NOT PROVEN**        |
| reachable AppleJPEG UAF                          | **NOT PROVEN**        |
| LPE                                              | **NOT PROVEN**        |

### Bottom line

The original reachability question is closed:

> **The JPEG path reaches the descriptor implementation whose `_dmaReferences` increment has no
> upper bound. Apple's 27.0 GM op-3 hardening does not protect this path.**

The severity question remains open.

The `_dmaReferences` route has a quantified and very high bar to memory unsafety. Separately, the
JPEG DMA teardown contains a much cheaper stale-command / double-release candidate that performs
a virtual call through the supplied `IODMACommand`, but the request-lifecycle and attacker-control
preconditions are not yet closed.

In short:

> **Reachable. Defective. Unfixed. Proven to use the unguarded descriptor implementation.
> Memory corruption is still not proven.**

---

## Research files

The repository preserves the audit chronologically rather than rewriting earlier conclusions.

| file                                  | role                                                                                         |
| ------------------------------------- | -------------------------------------------------------------------------------------------- |
| `priv24A435_xnu_refcount_findings.md` | original `_dmaReferences` guard analysis                                                     |
| `priv24A435_xnu_reachability.md`      | first producer/reachability pass                                                             |
| `priv24A435_dma_refcount_leak.md`     | increment/decrement asymmetry                                                                |
| `priv24A435_dmaref_consumer.md`       | counter consumers                                                                            |
| `priv24A435_dma_producer_reach.md`    | producer/gating survey                                                                       |
| `priv24A435_kernel_rw_candidates.md`  | broader candidate sweep                                                                      |
| `priv24A435_mvhevc_signed_index.md`   | MV-HEVC signed-index investigation                                                           |
| `priv24A435_kernel_rw_round3.md`      | full shared-cache sweep and defused hypotheses                                               |
| `priv24A435_27_2b1_diff_verdict.md`   | cross-build validation and JPEG client tracing                                               |
| `priv24A435_reach_full_chain.md`      | descriptor-class proof, complete JPEG→unbounded-op5 chain, UAF attempt and DMA teardown lead |

Earlier documents intentionally remain unchanged where possible so that mistakes, corrections and
the evolution of the investigation are visible.

---

## Methodology notes

Several analysis mistakes produced useful reusable lessons:

* ARM64E chained pointers: **bit 63 = auth, bit 62 = bind**.
* Authenticated rebases must not be interpreted as unresolved imports.
* Extracted kext `LC_SEGMENT_64` addresses are the authoritative runtime VA map used here.
* Kernelcache section-based scans can silently fail where segment scans work.
* `blraa` is a call and returns; treating it as a CFG terminator produces false loop results.
* Direct caller counts are insufficient for `IOCommandGate` actions and other indirect callbacks.
* Matching structure offsets across unrelated kernel objects are not evidence that the fields have
  the same semantics.
* Source-looking or textual diffs are leads; the final claims are based on machine-code paths.

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
