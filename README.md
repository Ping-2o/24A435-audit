# PRIV-24A435 audit

> [!IMPORTANT]
> This repository is research-assisted by AI agents.

> [!NOTE]
>
> ### Open Research
>
> Contributions, independent verification, and corrections are welcome.

Static-audit dossier centered on **iOS 27.0 GM 24A435 (iPhone17,5)**, with cross-version
validation against **27.0 release 24A437** and **27.2 beta 1 24B5084k**.

The research covers the `_dmaReferences` kernel refcount line (LINE C), its producer and
consumer paths, client-side reachability through AppleJPEGDriver, the MV-HEVC signed index,
the AVE2 signed-product loop bound, and the full shared-cache sweeps used to validate or
defuse candidate bug classes.

Top-level verdict remains conservative:

> **No app-reachable memory-corruption vulnerability has been proven.**
>
> The `_dmaReferences` defect is, however, byte-verified across multiple builds, has a real
> consumer, has an unbalanced increment path, and now has a client-to-kernel JPEG path traced
> down to the DMA refcount increment. What remains unproven is a practical drive to the
> critical counter state and a resulting memory-safety consequence.

---

## 1. The document set

| # | file                                  | round | question it answers                                                  | verdict in one line                                                                                                                                                                                                                                                                                                                                                                               |
| - | ------------------------------------- | ----- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | `priv24A435_xnu_refcount_findings.md` | 1     | What did the GM `_dmaReferences overflow` fix actually add?          | A **signed, post-increment** compare on a 16-bit counter — live only in `[0x4000,0x7fff]`, bypassed after the sign bit is set and eventually wrapping to 0. *(Ownership/op-number claims corrected by later rounds.)*                                                                                                                                                                             |
| 2 | `priv24A435_xnu_reachability.md`      | 1→2   | Can producer paths reach the increment?                              | **Four kernel-side chains** (JPEG / ProRes / SEP / NVMe) reach the `ldaddh ++`; the two increment implementations are complementary on `cmd->[0x40]`, while the GM bound covers only one. *(Several early negative claims are corrected by #3–#5 and #9.)*                                                                                                                                        |
| 3 | `priv24A435_dma_refcount_leak.md`     | 2     | Is there an unbalanced increment capable of driving refcount drift?  | **Yes, byte-exact**: the map worker retains through the unchecked helper without the `desc+0x98` test while op-6 release is `+0x98`-gated → permanent +1 drift on the asymmetric path. *(Its non-atomic-reset candidate is DEFUSED by #8.)*                                                                                                                                                       |
| 4 | `priv24A435_dmaref_consumer.md`       | 2     | Does anything consume `refs == 0` as a meaningful state?             | **Yes**: `complete()` reads `+0x34` with `ldrh` and fatally asserts on non-zero DMA references. The counter therefore protects a real lifetime/teardown invariant rather than being dead bookkeeping.                                                                                                                                                                                             |
| 5 | `priv24A435_dma_producer_reach.md`    | 2     | Which producer kexts appear gated?                                   | Maps **39 producer kexts / 120 bind sites** and develops the two-signal gate test. Its early producer ranking is superseded where later binary/plist/client analysis provides stronger evidence.                                                                                                                                                                                                  |
| 6 | `priv24A435_kernel_rw_candidates.md`  | 2     | What other candidate memory-safety shapes exist?                     | Not three primitives: **C1 = AVE2 signed-product loop bound**, **C2 = MV-HEVC signed index**, plus framework triage and a checked-clean list.                                                                                                                                                                                                                                                     |
| 7 | `priv24A435_mvhevc_signed_index.md`   | 2     | What is the strongest signed-index hit?                              | `CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb`: a 64-entry array, signed-only guard, negative indices accepted, pointer-table load, pointer returned. The only instance of this shape found in the searched corpus.                                                                                                                                                                      |
| 8 | `priv24A435_kernel_rw_round3.md`      | 3     | What does the full shared-cache sweep change?                        | Closes the searched sign-extend→signed-compare class, confirms the `_dmaReferences` consumer, **DEFUSES** the non-atomic reset, and closes the naïve 65,536-prepare M2ScalerCSC wrap path because a fresh `IODMACommand` is created per prepare.                                                                                                                                                  |
| 9 | `priv24A435_27_2b1_diff_verdict.md`   | 4     | Did Apple change the refcount logic, and can a real client reach it? | **No relevant fix in 27.2b1:** the guard and retain/decrement sites remain byte-equivalent. Identifies the checked/unchecked descriptor families, finds the real JPEG userspace clients, verifies selector dispatch through `IOCommandGate::runAction(queue_io_gated)`, and closes the client→driver→DMA increment chain at the binary level. Runtime wrap and memory corruption remain unproven. |

---

## 2. Status ledger — current

### Proven, byte-exact

* `_dmaReferences` is a **16-bit atomic counter** at `IOMemoryDescriptor + 0x34`.

* The checked increment performs:

  `ldaddh ++ → cbz → sxth → cmp #0x4000 → b.lt`

  The comparison therefore interprets the old 16-bit value as signed. Values with bit 15 set
  become negative and satisfy the signed `< 0x4000` branch.

* The check occurs **after the atomic increment**. It does not prevent the increment itself.

* Enumeration of the relevant atomic sites is unchanged between **24A435 and 24B5084k**:
  **4 sites total / 1 bounded / 3 unbounded**, with the same roles.

* The out-of-line RETAIN helper remains an increment with **no `#0x4000` bound**.

* The decrement remains guarded by an **unsigned `ldrh`** zero check before its atomic decrement.

* The checked and unchecked `dmaCommandOperation` families have been identified at the class level:

  * `IOGeneralMemoryDescriptor` → checked path
  * `IOBufferMemoryDescriptor` → unchecked path

* A real consumer exists. `IOMemoryDescriptor::complete()` reads `_dmaReferences` and treats
  non-zero references as a fatal invariant violation:

  `complete() while dma active @ IOMemoryDescriptor.cpp:5331`

* The asymmetric map/release path is byte-verified: an acquire can increment without the
  corresponding `desc+0x98` condition while the release side is `+0x98`-gated, providing an
  **unbalanced +1 drift mechanism**.

### Cross-version validation

The `_dmaReferences` guard is confirmed present in:

* **27.0 GM — 24A435**
* **27.0 release — 24A437**
* **27.2 beta 1 — 24B5084k**

In 27.2b1, the important instruction sequence is unchanged apart from relocation and source-line
movement. The RETAIN helper and decrement are likewise byte-equivalent.

This makes the finding stronger than a GM-only artifact: the same refcount logic survived into a
later beta without the signedness/asymmetry being removed.

---

## 3. JPEG reachability

Round 4 substantially tightens the original reachability claim.

### Kernel side

The AppleJPEG path reaches:

```text
AppleJPEGDriver
  → userclient selector
  → IOCommandGate::runAction(queue_io_gated)
  → queue_io_gated
  → setupBuffersForCoding_gated /
    doRestOfBufferSetupFor{Decode,Encode}_gated
  → AppleJPEGDart::mapMemoryDescriptor
  → IODMACommand::setMemoryDescriptor
  → dmaCommandOperation
  → _dmaReferences increment
```

The earlier assumption that `queue_io` itself was the unique bottleneck was incorrect.
`queue_io_gated` is the shared action dispatched indirectly through `IOCommandGate`.

Six selector implementations materialize the same gated action:

```text
1, 3, 4, 5, 6, 7
    ↓
IOCommandGate::runAction(queue_io_gated)
```

This matters because indirect gate actions have **zero ordinary direct callers**; caller-count
analysis alone incorrectly makes them look unreachable.

### Client side

The dyld shared cache identifies the actual JPEG clients.

`JPEGH1.videodecoder` performs:

```text
IOServiceMatching("AppleJPEGDriver")
  → IOServiceGetMatchingService
  → IOServiceOpen
  → IOConnectCallStructMethod(selector 7)
```

Its selector-7 request uses **3488-byte input and output structures**, matching the kernel
external-method dispatch record for selector 7.

Inside the selector-7 implementation, the kernel materializes the address of
`queue_io_gated` and passes it to `IOCommandGate::runAction`.

`JPEGH1.videoencoder` independently uses selector 6, which reaches the same gated action.

The client-side and kernel-side pieces therefore join:

```text
VideoToolbox
  → JPEGH1.videodecoder
  → AppleJPEGDriver
  → selector 7
  → IOCommandGate::runAction(queue_io_gated)
  → AppleJPEGDart::mapMemoryDescriptor
  → IODMACommand
  → _dmaReferences
```

This is a **static, binary-verified reachability chain**. It does not by itself prove that an
arbitrary sandboxed application can drive the counter to a dangerous state.

---

## 4. Entitlement / sandbox findings

The kernelcache's `__PRELINK_INFO` contains the embedded kext Info.plists, allowing the
userclient configuration to be checked without relying on the restore filesystem.

Across the examined kernel collections:

* no kext declares `IOUserClientEntitlements`;
* AppleJPEGDriver contains no class-specific `com.apple.private.*` entitlement string;
* ProRes, SEPManager, and NVMe do contain explicit entitlement strings.

The compiled sandbox data also contains references to `AppleJPEGDriver` and
`AppleJPEGDriverUserClient`.

An important distinction emerged during the analysis:

* `AppleJPEGDriverUserClient` appears in explicit `iokit-user-client-class` contexts associated
  with Apple-internal/test and Accessory/CarPlay profile groups;
* the WebKit-related region contains `AppleJPEGDriver` as a **service/registry-entry class**,
  not the `AppleJPEGDriverUserClient` class.

Therefore, the mere presence of JPEG-related names in the sandbox blob is **not sufficient**
to claim unrestricted application access. Exact sandbox semantics and the applicable compiled
profile still matter.

---

## 5. Other findings

### MV-HEVC signed index

`CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb` remains the only real instance of the
searched sign-extend→signed-compare indexing shape found across the corpus.

The relevant properties remain:

* 64-entry array;
* signed comparison;
* negative values pass the upper-bound check;
* sign-extended value is subsequently used as an index;
* the resulting pointer is returned.

This is a real suspicious primitive shape, but its surrounding process boundary and attacker
control must be kept separate from the kernel `_dmaReferences` finding.

### AVE2

The original AVE2 signed-product loop-bound candidate remains worth tracking, but the 27.2b1
diff did **not** reveal a clean security fix for it.

The apparent:

```text
sMBStats → sMBStats[m]
```

change was initially misleading. Direct extraction showed the actual transition was:

```text
sMBStats → saMBStats[m]
```

consistent with a scalar-to-array refactor carrying per-element validation.

It is therefore **not currently evidence of a patched 24A435 vulnerability**.

### IONVMeFamily

IONVMeFamily changed substantially in 27.2b1, including removal of the
`fSanitizeInProgress == true` assertion and addition of sanitize-status strings.

That is a diff lead, not evidence of a vulnerability. Any NVMe reachability conclusions that
depend on changed code should be revalidated against the newer build.

---

## 6. Defused / closed

Do not reopen these without new evidence:

* **Non-atomic reset** at `0xfffffff00b346888`: no branch targets; both entrances occur
  pre-teardown.

* **Naïve 65,536-prepare M2ScalerCSC wrap**: the reachable path creates a fresh
  `IODMACommand` per prepare, so repeated prepares do not accumulate 65,536 references on the
  same command/descriptor through that route.

* **Generic sign-extend → signed-compare sweep**: only the MV-HEVC site survived semantic
  triage in the searched corpus.

* **AVE2 27.2b1 scalar→array change as a patch signal**: downgraded; current evidence supports
  refactoring rather than a repaired missing bound.

* **`+0x34` VLAN refcount lead**: unrelated BSD `ifvlan` object. It is a separate 32-bit
  refcount at the same structure offset and must not be conflated with
  `IOMemoryDescriptor::_dmaReferences`.

* Checked-clean / already-triaged areas include decmpfs, APFS narrow-value hits, lifs/tmpfs,
  and the previously sampled framework narrowing patterns.

---

## 7. What is still not proven

The remaining gap is deliberately narrow.

### Counter drive

Static analysis proves that the counter can drift and that the checked comparison becomes
ineffective once the 16-bit value crosses into the signed-negative range.

It does **not** yet prove that a realistic externally controlled execution can accumulate the
required number of outstanding references on one descriptor.

There is currently no runtime reproducer demonstrating the `_dmaReferences` value reaching
`0x8000` or wrapping to zero.

### Memory-safety consequence

The `complete()` consumer establishes that zero/non-zero state participates in a real DMA
lifetime invariant.

That is still different from proving:

```text
counter corruption
  → premature completion / teardown
  → stale DMA or object lifetime
  → UAF / arbitrary memory corruption
```

No such end-to-end memory-corruption sequence has been demonstrated.

### Exploitability

No kernel read/write primitive, privilege escalation, sandbox escape, or exploit chain is
claimed by this repository.

---

## 8. Current verdict

The strongest supported statement is:

> `_dmaReferences` contains a byte-verified refcount hardening defect involving a signed
> comparison on a 16-bit atomic counter, an unchecked complementary increment path, and an
> independently demonstrated unbalanced-increment mechanism. A real consumer of the counter
> exists, the relevant logic survives across 27.0 GM, 27.0 release, and 27.2 beta 1, and the
> AppleJPEG client-to-DMA-increment path has been statically traced at the binary level.
>
> What remains unproven is a practical drive to the critical counter state and a resulting
> memory-safety consequence.

Accordingly:

**No app-reachable memory-corruption vulnerability is claimed as proven.**

The evidence is stronger than a standalone hardening observation, but it does not justify
calling the finding an exploitable kernel vulnerability without runtime confirmation of the
remaining lifetime transition.

---

## 9. Research methodology

The repository intentionally keeps corrections and negative results.

Important lessons from the later rounds:

* string/symbol diffs are useful for locating changed components, but **binary verification is
  authoritative**;
* version bumps do not imply code changes;
* indirect callbacks such as `IOCommandGate` actions cannot be classified using direct caller
  counts;
* identical structure offsets across unrelated classes do not imply identical fields;
* entitlement strings, Info.plist properties, service-class sandbox grants, and
  userclient-class sandbox grants are distinct signals;
* a suspicious source-level-looking diff is not a security fix until the relevant machine-code
  path is traced.

Claims should therefore be reproducible from the supplied scripts, extracted binaries, addresses,
instruction sequences, and cross-build comparisons rather than inferred from naming alone.

---

> [!NOTE]
>
> ### Disclaimer
>
> This repository documents static security research and reverse engineering.
>
> All claims are intended to be independently checkable and should be re-verified before being
> relied upon.
>
> No exploit code is included or claimed. The material is provided for educational and defensive
> research purposes.
