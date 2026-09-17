# PRIV-24A435 LINE C — which kexts can drive the xnu DMA-bind path, and which are gated

Target: iOS 27.0 GM **24A435** (iPhone17,5), kernel collection (300 kexts, local carve).
Reproduce: `python3 analysis/priv24A435/dma_producer_reach.py`

Companion to `priv24A435_dma_refcount_leak.md` (the xnu-side defect) and
`priv24A435_xnu_reachability.md` (the chains). This file answers the reachability
question at the level that actually gates it: **not which kexts call the path, but which
kexts call it and leave their userclient ungated.**

---

## 0. HEADLINE

1. **39 kexts / 120 call sites** drive `IODMACommand::setMemoryDescriptor` (slot `0x88`,
   div `0xb91`) into the xnu map path — the surface the defect lives on.
2. **A validated two-signal gate test** classifies all 39. It corrects the reachability
   note in one place of consequence: **`AppleJPEGDriver` is entitlement-gated** — the
   note calls it *"imaging (ImageIO, least-gated app surface)"*, and that is wrong.
3. **All four chains in `priv24A435_xnu_reachability.md` §1 are gated.** JPEG (property
   key), ProRes (property key), SEP (name check), NVMe (name check).
4. **One producer is both gate-signal-free and app-facing and already proven reachable
   on device: `AppleM2ScalerCSCDriver`** — one bind site, function
   `0xfffffff0090d0470`. That is the only driver in the collection that can plausibly
   carry the defect to an app, and it is the one the campaign's row I already opened
   from a sandboxed app (26.6, byte-proven HW DMA, v169).

---

## 1. Method — why a keyword grep is not good enough

The obvious census is "does the kext carry `com.apple.private.*` strings". It has a
**proven false negative**: AppleAVD's gate value is
`com.apple.videotoolbox.hardwarevideodecoder`, which contains neither `entitle` nor
`private`, and is **not present as a string in the AVD kext at all**.

The gate is installed by setting the `IOUserClientEntitlements` property, so the
decisive artefact is a **code reference to that property-key string**. The test is:

1. locate the `IOUserClientEntitlements\0` string in `__cstring`;
2. scan every executable section for an `adrp`+`add` materialising its address.

Validated against three cases with known ground truth **before** being trusted:

| kext | key xrefs | ground truth | agrees? |
|---|---|---|---|
| `com.apple.driver.AppleAVD` | 1 (`0xfffffff0086abe14`) | gated (`REPORT_AVD`, AGENTS.md) | yes |
| `com.apple.driver.AppleAVE2` | 1 (`0xfffffff00887f934`) | gated (`AVE_Entitlement_Check`) | yes |
| `com.apple.driver.AppleM2ScalerCSCDriver` | no key at all | ungated (row I opened it) | yes |

**Second false negative, found while running it:** `AppleSEPManager` has **no key** but
carries `com.apple.private.applesepmanager.allow` and checks it directly. So the key test
alone is also insufficient. A kext is only a **strong candidate** when **neither** signal
is present. That two-signal rule is what the classification below uses.

---

## 2. Result

### [1] STRONG CANDIDATES — neither gate signal (18)

| kext | bind fns | userclient |
|---|---|---|
| `com.apple.driver.AppleS8000AES` | 8 | none by name |
| `com.apple.driver.ApplePIODMA` | 4 | none by name |
| `com.apple.driver.AppleOnboardSerial` | 3 | none by name |
| `com.apple.driver.AppleUSBXDCI` | 3 | none by name |
| `com.apple.driver.AppleIISController` | 2 | none by name |
| `com.apple.driver.AudioDMAController-T8140` | 2 | none by name |
| `com.apple.driver.usb.AppleUSBXHCI` | 2 | none by name |
| `com.apple.driver.AppleA7IOP` | 1 | none by name |
| **`com.apple.driver.AppleM2ScalerCSCDriver`** | **1** | `asynchronousUserClient` |
| `com.apple.driver.AppleMobileDispH17P-DCP` | 1 | none by name |
| `com.apple.driver.AppleSPIMC` | 1 | none by name |
| `com.apple.driver.AppleThunderboltNHI` | 1 | none by name |
| `com.apple.driver.IOSlaveProcessor` | 1 | none by name |
| `com.apple.driver.RTBuddy` | 1 | `RTBuddyUserClient` |
| `com.apple.driver.usb.AppleSynopsysUSBXHCI` | 1 | none by name |
| `com.apple.iokit.IONetworkingFamily` | 1 | `IONetworkUserClient` |
| `com.apple.iokit.IOSkywalkFamily` | 1 | none by name |
| `com.apple.iokit.IOStorageFamily` | 1 | none by name |

13 of the 18 have **no userclient class name at all**, i.e. they are kernel-internal
clients of the DMA path and are not directly app-driven. That leaves five with a
userclient surface: **M2ScalerCSC, RTBuddy, IONetworkingFamily**, and the two whose class
names did not resolve. Of those, only M2ScalerCSC has an on-device open proof.

### [2] GATED BY PROPERTY KEY (9)

`AppleARMPlatform` (2 xrefs), `AppleAVD` (1), `AppleH16ANEInterface` (2),
`IOMobileGraphicsFamily` (1), `AppleAVE2` (1), **`AppleJPEGDriver` (1, `0xfffffff009022810`)**,
`AppleProResHW` (1, `0xfffffff0093cda24`), `AppleSmartIO2` (1), `com.apple.kernel` (3).

### [3] GATED BY NAME ONLY (no key, entitlement-name strings present)

`IONVMeFamily` (44 bind fns — the largest producer, and it has
`CheckEntitlementForSelector`), `IOACIPCFamily`, `IOThunderboltFamily`,
`AppleSEPManager`, `ApplePMP`, `AppleH16CameraInterface`, `AppleConvergedPCI`,
`AppleConvergedIPCBBControl`, `IOAVFamily`, `IOPAudioIOBufferDevice`,
`IOUSBHostFamily`.

---

## 3. What this corrects

`priv24A435_xnu_reachability.md` §1.1 presents `AppleJPEGDriver` as:

> *imaging (ImageIO, least-gated app surface)*

**It is gated.** `AppleJPEGDriver` carries `IOUserClientEntitlements` and materialises it
at `0xfffffff009022810`. The note asserted "least-gated" without a code-level gate check;
its §1.2–§1.4 entries are gated too, and §1.4 says so for NVMe. So:

> **Every one of the four "complete chains" in that note terminates in an
> entitlement-gated userclient.** "Chain from userclient selector to `ldaddh ++`"
> is a chain from a selector no third-party app can reach.

This does not invalidate the reachability analysis — the chains are real, and the
complementary-branch defect is real. It does invalidate the framing that the chains
constitute an *app-facing* surface.

---

## 4. What is proven / not proven

**Proven, byte-exact:**
1. 39 producer kexts, 120 bind sites, independently reproducing
   `reach/slot88_setmemdesc.txt`.
2. The two-signal gate test, validated on three ground-truth cases with one agreeing
   result each.
3. `AppleJPEGDriver` is gated by `IOUserClientEntitlements` set in code
   (`0xfffffff009022810`), as are AVD, AVE2, ProRes, SmartIO2, ARMPlatform, H16ANE,
   IOMobileGraphicsFamily.
4. `AppleM2ScalerCSCDriver` has neither gate signal anywhere in its binary, has one bind
   site (`fn 0xfffffff0090d0470`), and is the driver row I opened from a standard container
   on 26.6 with byte-proven HW DMA (v169).

**Not proven:**
1. That `AppleM2ScalerCSCDriver` is still openable **on 27.0 GM**. §5 of
   `PRIV_HUNT_24A435.md` already flags this: row I's proof is on 26.6, and on 27.0 it is
   an inference from "no gate was added". The gate test here strengthens the inference
   (no gate key, no name check) but is not an on-device result.
2. That M2ScalerCSC's single bind site reaches the specific map path from §0 of
   `priv24A435_dma_refcount_leak.md` with the arguments that break the `+0x98` invariant.
   The bind site is `fn 0xfffffff0090d0470`; whether its `prepare` call takes the
   `op-1` route with `x5 != 0` / a differing device address is unexamined.
3. That the counter can be driven to the bound. Unchanged — still static only.
4. Anything about the `RTBuddy` / `IONetworkingFamily` userclients being app-openable.
   They are gate-signal-free but untested.

---

## 5. Honest ceiling — what this does and does not buy

This narrows "which kexts can call them" from 39 drivers to **one** with an existing
on-device open proof, which is real progress on reachability. It buys **nothing** toward
kernel read/write:

* The defect reached is a **refcount field on a DMA command/mapping object**. There is no
  read of it into a user buffer, and no write of a user value through it.
* There is still **no leak primitive** anywhere in the tree
  (`grep -ri 'kread\|kwrite\|arbitrary read'` over the repo: zero matches), and no write
  primitive. A kernel r/w chain needs at least one of each, plus a way past PPL/KTRR/PAC.
* The campaign's own top-level assessment stands unchanged:
  `REPORT_27_0_CVE_HUNT.md` — *"no app-reachable memory-corruption vulnerability was
  proven in 24A435."*

So: this maps the road, it does not arrive. The remaining work to a primitive is
step (2) above (does the reachable bind site take the vulnerable branch), then the
`+0x98`/reset reachability question, then a primitive that does not currently exist.

---

*Artifacts: `analysis/priv24A435/dma_producer_reach.py` (gate test + classification),
`analysis/priv24A435/reach/slot88_setmemdesc.txt` (bind inventory),
`analysis/priv24A435/reach/batch_chain_out.txt` (per-kext closure + selector hits).
Method note: two gate signal classes had to be found (the keyword miss on AVD's
entitlement value, and the key miss on SEPManager) before the classification was stable —
each was caught by testing the signal against a case with known ground truth.*
