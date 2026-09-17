# PRIV-24A435 audit

> [!IMPORTANT]
> This repository is research-assisted by AI agents

> [!NOTE]
> ### Open Research
> Contributions are welcome

Static-audit dossier for **iOS 27.0 GM 24A435 (iPhone17,5)**: the `_dmaReferences` kernel
refcount line (LINE C), the MV-HEVC signed index, the AVE2 signed-product loop bound, and the
round-3 full shared-cache sweep that closes the class.

Top-level verdict inherited unchanged from `REPORT_27_0_CVE_HUNT.md`: *"no app-reachable
memory-corruption vulnerability was proven in 24A435."*

---

## 1. The document set

| # | file | round | question it answers | verdict in one line |
|---|---|---|---|---|
| 1 | `priv24A435_xnu_refcount_findings.md` | 1 | What did the GM `_dmaReferences overflow` fix actually add? | A **signed, post-increment** compare on a 16-bit counter — live only in `[0x4000,0x7fff]`, silently bypassed at `0x8000`, wraps to 0. *(Ownership/op-number claims corrected by #2 and #3.)* |
| 2 | `priv24A435_xnu_reachability.md` | 1→2 | Can app-facing selectors reach the increment? | **Four complete chains** (JPEG / ProRes / SEP / NVMe) selector → `ldaddh ++`; the two increment paths are exact complements on `cmd->[0x40]`, and the GM bound covers only one. *(Its "no consumer" and "no unbalanced increment" claims are refuted by #4 and #3; its "JPEG least-gated" claim by #5.)* |
| 3 | `priv24A435_dma_refcount_leak.md` | 2 | Is there an unbalanced increment (a driver for the drift)? | **Yes, byte-exact**: the map worker retains via the unchecked helper with no `desc+0x98` test while op-6's release is `+0x98`-gated → permanent +1 drift per unguarded call. *(Its §6.3 "non-atomic reset = stronger candidate" is DEFUSED by #8.)* |
| 4 | `priv24A435_dmaref_consumer.md` | 2 | Does anything *consume* `refs == 0` as "no DMA in flight"? | **The consumer exists**: `complete()` (`0xb341718`) reads `+0x34` with `ldrh` and fatally asserts `complete() while dma active @ IOMemoryDescriptor.cpp:5331` — the line is a UAF *precondition*, not just a hardening gap. |
| 5 | `priv24A435_dma_producer_reach.md` | 2 | Which of the 39 producer kexts are gated? | Validated **two-signal gate test**; all four #2 chains are entitlement-gated; **`AppleM2ScalerCSCDriver` is the only gate-signal-free + app-facing producer** (one bind site, `0xfffffff0090d0470`). |
| 6 | `priv24A435_kernel_rw_candidates.md` | 2 | "3 ways to kernel r/w?" — honestly | Not 3 primitives: **C1 = AVE2 signed-product loop bound** (kernel, one trace from a verdict), **C2 = MV-HEVC signed index** (daemon-side, → #7), plus a frameworks sample; also the checked-clean list (decmpfs, apfs, lifs/tmpfs). |
| 7 | `priv24A435_mvhevc_signed_index.md` | 2 | The one hit of the sweep's class, in full | `CAVDMvHevcDecoder::releaseUnusedPicturesFromOneSubDpb` (`0x22a382dfc`): 64-entry array (`_parseHevcSps` hard-codes `#0x40`), guard is a **signed `b.le`** (every negative passes), result index-loads a pointer table and **returns** it. The only instance of its shape in 309 binaries. |
| 8 | `priv24A435_kernel_rw_round3.md` | 3 | What does the full 1,056-image cache sweep change? | Class **closed** across the new corpus (same single hit); consumer **confirmed real** (refutes #2's §6.1 via #4); non-atomic reset **DEFUSED** (fall-through-only, both entrances pre-teardown); the 65,536-prepare wrap **closed on the reachable path** (M2ScalerCSC's bind helper creates a fresh `IODMACommand` per prepare, no reuse test). Leads re-ranked. |

---

## 2. Status ledger (as of round 3, #8)

**Proven, byte-exact**

- The `_dmaReferences` bound is a signed `sxth`+`b.lt #0x4000` compare evaluated *after* an
  unconditional atomic increment; `[0x8000,0xffff]` passes and the counter walks to 0. The
  decrement reads unsigned, compounding the drift.
- Two complementary increment branches on `cmd->[0x40]`: `==0` → checked op-3 (impl A);
  `!=0` → unchecked op-5 via the out-of-line retain helper `0xb3409a4` (no bound at all).
- The consumer: `ldrh [x0,#0x34]` → `cbnz` → non-returning assert
  `complete() while dma active @ IOMemoryDescriptor.cpp:5331` (`0xfffffff00b343bdc`).
- The guard asymmetry: acquire at `0xb34612c` has no `desc+0x98` test; op-6 release at
  `0xb34571c` is `+0x98`-gated.
- The producer gate map: 39 kexts / 120 bind sites; two-signal test validated on three
  ground-truth kexts; M2ScalerCSC sole gate-signal-free app-facing producer.
- MV-HEVC: 64-entry array (proven by `_parseHevcSps`'s `#0x40` copy), signed-only guard,
  unbounded sign-extended index used twice, pointer returned at `0x22a382f44`.
- AVE2 `0xfffffff00886b170`: loop bound = signed product of two signed bytes (`ldrsb`×`ldrsb`→
  `mul`), no relation to the caller's array length.

**Defused / closed**

- Non-atomic reset `0xfffffff00b346888`: zero branch targets; both entrances pre-teardown.
- 65,536-prepare wrap: not reachable through M2ScalerCSC (fresh command per prepare, out-pointer
  written unconditionally, no reuse check).
- Sign-extend→signed-compare class: exactly 1 real hit across ~1,365 binaries (the MV-HEVC site);
  the rest are string loops, signed loop counters, and length compares.
- Checked-clean (do not redo): `AppleFSCompressionTypeZlib`/decmpfs (guard correct), apfs's 246
  narrow hits (Unicode sentinel idiom), lifs/tmpfs (nothing), framework `narrow` triage samples.

---

> [!NOTE]
> ### Disclaimer
> All claims cite checkable artifacts; re-verify before
trusting any of them. No exploit code is included.
> use only for educational purposes. No exploit code.
