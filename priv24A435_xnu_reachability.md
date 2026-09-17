# PRIV-24A435 LINE C — `_dmaReferences`: full chains across driver types, and the unchecked increment

Target: iOS 27.0 GM **24A435** (iPhone17,5). Kernel `com.apple.kernel` plus the other 299 kexts
of the collection.

Supersedes `priv24A435_xnu_reachability.md` (now folded in here). The root-cause note
`priv24A435_xnu_refcount_findings.md` still stands for the *shape* of the hole
(post-increment, signed compare, wrap to zero).

---

## 0. HEADLINE

1. **Four complete chains, four different driver types**, each closed from the userclient
   `IOExternalMethodDispatch` **selector number** down to the `ldaddh ++`:
   imaging (JPEG), video codec (ProRes), security coprocessor (SEP), storage (NVMe). §1.
2. **The open item from the previous pass is resolved**: the out-of-line `RETAIN` helper that
   increments `IOMemoryDescriptor+0x34` **with no bound check** acts on **the same descriptor
   object** as the checked inline path. §3.
3. **The two increment paths are exact complements on one field (`cmd->[0x40]`), and both are
   reached by the same driver operation the app-facing selectors drive.** `== 0` → the checked
   op-3 path; `!= 0` → the **unchecked** op-5 path. So the GM bound covers one of the two
   branches that increment the counter. §3.4–§3.5.

---

## 1. FULL CHAINS

### 1.1 AppleJPEGDriver — imaging (ImageIO, least-gated app surface)

```
  app (ImageIO encode/decode)
   ▼
  AppleJPEGDriverUserClient::externalMethod
       IOExternalMethodDispatch table @ 0xfffffff008078860, 10 records, 40-byte stride
       sel 1 -> 0x9022da4   (structIn  88)      *** reaches the pin
       sel 3 -> 0x9022de4   (structIn  88)      *** reaches the pin
       sel 5 -> 0x9022e4c   (structIn 4096)     *** reaches the pin
       sel 0 -> 0x9022d98   sel 2 -> 0x9022dd8   sel 4 -> 0x9022e18
       sel 6 -> 0x9022e80   sel 7 -> 0x9022eb4   sel 8 -> 0x9022ee8   sel 9 -> 0x9022f18
   ▼
  AppleJPEGDriver::queue_io(OSObject*, void*, IOExternalMethodArguments*)   0xfffffff009019334
   ▼
  IOCommandGate::runAction -> AppleJPEGDriver::queue_io_gated(JpegRequest*) 0xfffffff009018c0c
       (indirect: the action pointer is materialised by adrp+add at
        0x9018a68, 0x90197e0, 0x9019d54, 0x901a284, 0x901a818, 0x901ada4)
   ├─► setupBuffersForCoding_gated         0xfffffff009017b78
   ├─► doRestOfBufferSetupForDecode_gated  0xfffffff0090171fc
   └─► doRestOfBufferSetupForEncode_gated  0xfffffff009017844
   ▼
  AppleJPEGDart::mapMemoryDescriptor(IOMemoryDescriptor*, uint32_t, IODMACommand**,
                                     IOPhysicalAddress*, s_debug*)          0xfffffff00902b1cc
   ▼
  IODMACommand::setMemoryDescriptor(desc, cache=true)   slot 0x88, div 0xb91   0xfffffff00b337ad8
       the pin call site: 0xfffffff00b337cc8
   ▼
  IOMemoryDescriptor::dmaCommandOperation(op 3, arg 1)  [w1 = 0x03000001]
       slot 0x90, div 0xa8a7, impl A = 0xfffffff00b3454d4
   ▼
       add x8, x0, #0x34 ; ldaddh ++ ; sxth ; cmp #0x4000 ; b.lt   <- checked path
```

### 1.2 AppleProResHW — video codec

```
  AppleProResUserClient::externalMethod
       dispatch table @ 0xfffffff00b8f23f8, 5 records, 40-byte stride
       sel 3 -> 0xfffffff0093cd7e4  (structIn 512)   *** reaches the pin
       sel 0 -> 0x93cd754 (20/24)   sel 1 -> 0x93cd774 (16)
       sel 2 -> 0x93cd7d8 (168)     sel 4 -> 0x93cd7f0
   ▼
  AppleProResHW::mapBufferWithDARTGated                                   0xfffffff0093c8cf8
   ▼
  IODMACommand::setMemoryDescriptor (slot 0x88)  ->  dmaCommandOperation(op 3, arg 1)
```

### 1.3 AppleSEPManager — security coprocessor (a *different* descriptor shape)

```
  AppleSEPManagerUserClient::externalMethod
       dispatch table @ 0xfffffff00813e768, 6 records, 24-byte stride (classic layout)
       sel 1 -> 0xfffffff009607e08   *** reaches the pin
       sel 0 -> 0x9607ddc   sel 2 -> 0x9607ed4 (out 20)   sel 3 -> 0x960803c
       sel 4 -> 0x96080a0   sel 5 -> 0x9608104 (out 12)
   ▼
  AppleSEPManager::addVisibleMemory(IOMemoryDescriptor*, IODMACommand**, UInt64*)
   ▼
  IODMACommand::setMemoryDescriptor (slot 0x88)  ->  dmaCommandOperation(op 3, arg 1)
```

### 1.4 IONVMeFamily — storage (44 bind sites, the largest producer)

```
  AppleNVMeUserClient / AppleNVMeSMARTUserClient::externalMethod
       (has AppleNVMeUserClient::CheckEntitlementForSelector -> entitlement-gated)
       selectors reaching the pin: 1, 2, 6, 7  across tables @0x82de3d0, @0x82e3698,
       @0x82e36b0, @0x82e3710, @0x82e3818
   ▼
  IOEmbeddedNVMeBlockDevice::writeData() / IONVMeLifeboatBlockDevice::readData(...)
  AppleANS2NVMeController::CreatePCIeUPDARTMapping()
  AppleEmbeddedNVMeController::CreateNamespaces(uint64_t, uint32_t)   0xfffffff00a1c6310
   ▼
  IODMACommand::setMemoryDescriptor (slot 0x88)  ->  dmaCommandOperation(op 3, arg 1)
```

### 1.5 Producer inventory (unchanged)

`IODMACommand::setMemoryDescriptor` (slot `0x88`, div `0xb91`) — **120 call sites across 37
kexts**. Full list: `reach/slot88_setmemdesc.txt`. Per-kext ancestor closures and named
driver entries: `reach/batch_chain_out.txt`.

Named driver entries recovered for the other producers:
`UnifiedPipeline2::dart_map_mdesc_gated(IOMemoryDescriptor*, IODMACommand**, dva_t*, bool)`
(IOMobileGraphicsFamily-DCP), `AppleSEPManager::addVisibleMemory(...)`.

---

## 2. METHOD NOTES ADDED THIS PASS

1. **Bridge indirect hops by searching for the target's address materialised in code.**
   `IOCommandGate::runAction` holds the action pointer, so the upward walk dead-ends at the
   gate. Searching the kext for `adrp+add` materialising the gated function's address
   (`fastxref.py`) yields the un-gated wrapper — for JPEG, six sites, all `queue_io`-family.
   The same trick resolves `IOTimer` callbacks, thread continuations and ops tables.
2. **Dispatch-table stride is not always 24.** JPEG and ProRes use **40-byte** records;
   SEPManager uses the classic **24-byte** `IOExternalMethodDispatch`. Detect the table as the
   longest run of consecutive records whose first word is an authenticated rebase into the
   kext's own text range — do not assume a stride.
3. **A table's base is not the first record you happen to find.** Anchor the run by requiring
   `len >= 3` and report the index relative to the run start, or the selector number will be
   off by however many records precede it.
4. The earlier traps still apply: `bl` targets the `bti c` (start−4); PAC diversity is per
   (declaring class, slot); chained-fixup target = `VA − 0xfffffff007004000`; `movk`'s shift
   is not a capstone operand; raw scans must not materialise a whole section.

---

## 3. THE UNCHECKED INCREMENT ACTS ON THE SAME OBJECT

### 3.1 The two slot-0x90 implementations

Both live in `IOMemoryDescriptor.cpp`, both at vtable slot `0x90` with diversity `0xa8a7`
(two overrides of one declared method):

| | address | size | vtables | string | refcount handling |
|---|---|---|---|---|---|
| **A** | `0xfffffff00b3454d4` | `0x944` | 4 | `IOGMD: not wired for the IODMACommand` | inline on op 1/3/6; **op 3 has the check** |
| **B** | `0xfffffff00b3406a4` | `0x300` | 5 | `fMapped %p %s %qx` | outlined helpers on op 5 (retain) / op 6 (release); op 3 unsupported |

### 3.2 The out-of-line RETAIN helper has no bound check

```
0xfffffff00b3409a4   RETAIN  (size 0xa0)                      4 call sites
    add  x8, x0, #0x34
    mov  w9, #1
    ldaddh w9, w8, [x8]        ; ++ on [x0+0x34]     <-- NO cmp #0x4000 anywhere
    cbnz w8, ret
    str  x19, [x0, #0x38]
    call sites: 0xb340818 (B op-5), 0xb34593c (A op-1), 0xb34612c, 0xb346208
```

### 3.3 The op-5 receiver IS the bound memory descriptor — proven

`IODMACommand::dmaCommandOperation` (`0xb33732c`) reaches this sequence:

```
0xfffffff00b33754c  ldp  w10, w11, [x21, #0x58]
0xfffffff00b337554  ldp  x19, x12, [x22, #0xb0]     ; x19 = internal->0xb0, else...
0xfffffff00b337590  cbz  x19, 0xfffffff00b3375c4
0xfffffff00b337594  ...  x19->vtable[0x20](x19)     ; retain
0xfffffff00b3375c4  ldr  x1, [x8, #0x48]            ; ... cmd->fMemory
0xfffffff00b3375cc  bl   0xfffffff00b337980        ; OSObject::setObject(&slot, fMemory)
0xfffffff00b3375d4  ldr  x19, [sp, #0x20]           ; x19 = the stored descriptor
0xfffffff00b3375ec  ldr  x8, [x16, #0x90]!          ; descriptor slot 0x90
0xfffffff00b3375f8  mov  w1, #0x5000000             ; op 5
0xfffffff00b337604  blraa x8, x16
```

`0xfffffff00b337980` is a **setter**, not a getter:

```
0xb337980(x0 = &slot, x1 = new)
    x20 = [x0] ; [x0] = x1
    if (x1)  x1->vtable[0x20](x1)      ; retain   (div 0x2e4a)
    if (x20) x20->vtable[0x28](x20)    ; release  (div 0x3a87)
```

So `x19` is `cmd->fMemory` (or the cached `internal->0xb0`, also a descriptor) — **the same
object** the checked op-3 path guards. B's op-5 handler then does `mov x0, x19`
(`0xb34080c`) and calls the RETAIN helper, which increments `descriptor+0x34` with no bound.

### 3.4 The two increment paths are COMPLEMENTARY — this is the finding

`IODMACommand::dmaCommandOperation` (`0xb33732c`) is called by
`IODMACommand::setMemoryDescriptor` itself, at `0xb337cfc`, as
`dmaCommandOperation(x1 = 0, x2 = 0, w3 = 1, w4 = 1)`. Walking its CFG:

```
0xb337390  ldp  w19, w9, [x0, #0x64]     ; w9 = cmd->[0x68]  (prepare count)
0xb337394  add  w10, w9, #1
0xb337398  str  w10, [x0, #0x68]
0xb33739c  cbz  w9, 0xb3373bc            ; prepare count WAS 0 -> first-bind path
              ... (else: cache check; on a cache hit -> return 0 at 0xb337904)
0xb3373bc  ...                            ; first-bind path
0xb33748c  cbnz w3, 0xb3374d8            ; w3 = 1, from setMemoryDescriptor
0xb3374d8  and  w8, w19, #0xf
0xb3374dc  cmp  w8, #2
0xb3374e0  b.ne 0xb337538                ; -> 0xb337538
0xb337538  ldr  x9, [x21, #0x40]         ; cmd->[0x40]
0xb33753c  cbz  x9, 0xb3378f4            ; if cmd->[0x40] == 0 -> BAIL, no op-5
0xb337554  ldp  x19, x12, [x22, #0xb0]   ; x19 = internal->0xb0
0xb337590  cbz  x19, 0xb3375c4           ; either way x19 ends up a memory descriptor
0xb3375c4  bl   0xb337980                ; OSObject::setObject(&slot, cmd->fMemory)
0xb3375e0  ...  ldr x8, [x16, #0x90]!    ; descriptor slot 0x90
0xb3375f8  mov  w1, #0x5000000           ; op 5
0xb337604  blraa x8, x16
```

Now compare the gate on the **pin** in `setMemoryDescriptor` (`0xb337c84`):

```
0xb337c84  ldr  x8, [x19, #0x40]         ; cmd->[0x40]
0xb337c88  cmp  x8, #0
0xb337c8c  cset w8, eq                   ; w8 = (cmd->[0x40] == 0)
0xb337c94  strb w8, [x9, #0x7e]          ; remember it for complete()
0xb337ca0  cbz  w8, skip                 ; pin iff cmd->[0x40] == 0
```

**The two gates are exact complements on the same field `cmd->[0x40]`:**

| `cmd->[0x40]` | `setMemoryDescriptor` | `dmaCommandOperation` | which implementation increments |
|---|---|---|---|
| `== 0` | issues descriptor-**op 3** (pin, +1) | bails at `0xb3378f4` | **A** — inline, *has* the `cmp #0x4000` check |
| `!= 0` | skips the pin entirely | proceeds to descriptor-**op 5** | **B** — `0xb34079c` → RETAIN helper, **no check at all** |

Verified: A's op-5 handler (`0xb345580`) touches `+0x90`/`+0x2*` only — it never reads or writes
`+0x34`. B's op-5 handler (`0xb34079c`) ends in `bl 0xb3409a4` (`0xb340818`), the unchecked
`ldaddh +1`.

### 3.5 Consequence — full reachability, and the fix is one branch short

Both increment paths are reached by **the same driver operation**, `IODMACommand::setMemoryDescriptor`,
which is itself reached from the app-facing userclient selectors in §1. So:

* **A-class descriptor, `cmd->[0x40] == 0`** → incremented by the checked path. The GM fix applies,
  with its signedness/post-increment hole.
* **B-class descriptor, `cmd->[0x40] != 0`** → incremented by the op-5 path. **The GM fix does not
  apply at all** — there is no bound on this path.

The counter is incremented on every bind either way; only the *branch* differs. That makes the
statement precise and binary-provable: **the `_dmaReferences overflow` bound added in iOS 27.0 GM
covers one of the two branches that increment the counter, and the branch it does not cover is
the one taken when `cmd->[0x40] != 0`.**

### 3.6 What is still open

* **The concrete class names of the A and B vtable groups** (4 and 5 vtables). A carries
  `IOGMD: not wired for the IODMACommand`; B carries `fMapped`. Resolving which drivers land in
  which group is what decides, per driver, whether the app-visible increment is the checked or
  the unchecked one. This is a naming exercise, not a reachability one — the reachability result
  above does not depend on it.
* **No runtime reproducer.** Nothing here demonstrates `_dmaReferences` actually reaching
  `0x8000`; it demonstrates that both increment paths are reachable from an app-driven selector
  and that one of them is unbounded. The wrap still needs ~32,768 outstanding references (or a
  leak), which is the remaining empirical question and the thing airlift's file primitive could
  help instrument (§5).

---

## 4. STATUS

**Proven, byte-exact:**
1. Four complete chains from userclient selector to `ldaddh ++`, across four driver types (§1).
2. The GM overflow check is a signed, post-increment compare live only in `[0x4000, 0x7fff]`,
   silently bypassed at `0x8000`, with the work path resuming.
3. The overflow log string has exactly **one** code reference (`0xb345560`); the underflow
   string has **two** (`0xb340b64`, `0xb345dd8`).
4. There are **two** slot-0x90 `dmaCommandOperation` implementations and **two** out-of-line
   refcount helpers; the checked path is one of four increment call paths.
5. The unchecked RETAIN helper's receiver is the same `cmd->fMemory` descriptor the checked
   path guards (§3.3), established via the `OSObject::setObject` at `0xb337980`.
6. **The two increment paths are exact complements on `cmd->[0x40]`** (§3.4): `== 0` → the
   checked op-3 path; `!= 0` → the unchecked op-5 path. Both are reached by
   `IODMACommand::setMemoryDescriptor`, i.e. by the same driver operation that the app-facing
   selectors in §1 drive. So the GM bound covers one of the two branches that increment the
   counter.
7. 120 producer sites across 37 kexts for `IODMACommand::setMemoryDescriptor`.

**Not proven:**
* The concrete class names of the A and B vtable groups, and therefore which drivers land on
  which branch (§3.6). The reachability result does not depend on it.
* That the counter can actually be driven to `0x8000` — no runtime reproducer: no selector
  exercised, no IOSurface built, no device test.

**Reportable now** (hardening, vendor-facing): the `_dmaReferences overflow` check added in
iOS 27.0 GM is (a) a signed compare on a 16-bit counter, (b) evaluated after the atomic
increment, and (c) enforced on only one of the two branches that increment the counter — the
branch taken when `cmd->[0x40] == 0`. The complementary branch (`cmd->[0x40] != 0`) increments
the same field through the out-of-line retain helper `0xb3409a4`, which contains no bound at
all. Recommend an unsigned post-increment test and a bound on every increment path.

---

## 5. EXTERNAL TOOLING — airlift (assessed, not used)

`https://github.com/0xjohnnydev/airlift` — MIT, commits 2026-09-14/15. An **AirTraffic/AFC
sandbox escape for iOS 27.0**, tested on 24A435 (this target build). From a paired Mac over
USB or Wi-Fi, no iOS app required, it abuses `-[ATAirlock processCompletedAsset:]`: the source
path is built from an unvalidated Books asset identifier (so `..` is accepted), the destination
is checked as a *string* with `hasPrefix:@"/var/mobile/Media/"` (so an ancestor symlink escapes
it), and the two `moveItemAtPath:` calls walk the payload out of Media. Confirmed fresh-file
writes in `/var/mobile`, `Documents`, `Library`, `Library/{Preferences,Caches,SpringBoard,SMS,
Safari}`, `Containers/**` and `/var/tmp`. Reads are indirect: move a known file into Media, read
it over AFC, move it back. Does not work on the MobileGestalt plist.

**Verdict: different layer — it does not advance the reachability question, but it is a usable
lab harness for the one gap that is still open.**

What it is *not*:
* It is a **filesystem primitive**, not code execution inside an app sandbox. It cannot put you
  at the top of the chain in §1, so it cannot demonstrate "reachable from a sandboxed app".
* It cannot read kernel memory, so it cannot observe `_dmaReferences` directly.
* It cannot create the ~32,768 concurrent bindings the wrap needs.

What it *is* good for, concretely:
1. **Runtime oracle.** The report's remaining gap is "no runtime reproducer". The cheapest
   signal that the bug is live is the `_dmaReferences overflow @%s:%d` log line. airlift's
   indirect read can pull files out of `/var/mobile/Library/Logs`, `Caches` and crash
   directories — enough to confirm whether the check fired, without a kernel debugger.
2. **Trigger harness.** Write access to `Media` and `Library/**` lets you place crafted media
   where the sync/media stack will ingest it, driving the JPEG/AVE/AVD decode paths repeatedly
   without writing an iOS app. This is the "make it happen 32k times" loop that is otherwise
   missing. Caveat: whether Books/media ingestion actually reaches ImageIO/VideoToolbox is
   unverified and should be checked before relying on it.
3. **State setup.** Writes into `Preferences` / `Caches` / `Containers` let you force device
   state before a trigger.

Caveats that matter:
* **Two days old and unaudited**, and its read path *moves real files* out of place and back.
  Read `airlift.py` and `Sources/` before running it; use a dedicated test device; do not point
  it at a device holding data you care about.
* It requires an already **trusted pairing**. That precondition matters: it is not a zero-click
  remote escape, and if it is ever cited it will be argued about on those grounds.
* Untested on 24A437 (README says "should also work").
* It is **someone else's bug**. Do not fold it into the `_dmaReferences` report — separate
  finding, separate credit to 0xjohnnydev, separate coordination with Apple. If it is used to
  reproduce, say so explicitly in the writeup.
* Sequencing risk: running an uncoordinated PoC on the same device/build while a disclosure is
  in flight can muddy attribution if it corrupts state or triggers an unrelated panic.

---

## 6. WHY THIS IS NOT (YET) A UAF — evidentiary gaps

The original LINE C note framed this as "the class the fix was meant to close (premature free
while DMA in flight)". After the reachability pass that framing is **not supported by anything
found in the binary**, and it should not go to Apple as a memory-safety claim. Being precise
here matters: an over-claimed UAF damages the credibility of the parts that *are* solid.

What is actually established: a 16-bit counter with a defective bound, on two complementary
branches, both reachable from app-facing selectors. That is a **counter-integrity defect**, not
a demonstrated use-after-free.

The specific things that would have to be true for it to be a UAF, and where each one stands:

1. **A consumer that treats `_dmaReferences == 0` as "no DMA in flight" and acts on it.**
   Not found. The only code that touches `descriptor+0x34` is: the inline op-3 increment
   (`0xb345530`), the inline op-3 decrement (`0xb345748`), the out-of-line retain helper
   (`0xb3409a4`), the out-of-line release helper (`0xb340a44`), and the two log sites. The
   `field_sweep.py` sweep over all 300 kexts found no other atomic on that offset in the
   `IOMemoryDescriptor` cluster. Nothing frees, tears down, or short-circuits on the value.
   If such a consumer exists it is outside that cluster and would be found by sweeping for
   *reads* of `descriptor+0x34` rather than atomics.
2. **The `+0x38` companion to be a teardown trigger.** It is not: it is a stored owner pointer,
   written on the 0→1 transition (`str x19, [x0, #0x38]` in the retain helper) and cleared on
   1→0 (`str xzr, [x0, #0x38]`). It records *who holds the reference*, and nothing reads it to
   decide a free.
3. **The counter to be reachable past `0x8000`.** Not demonstrated. The increment is one per
   bind, and the practical obstacle is the concurrency requirement: ~32,768 outstanding
   references on a single `IOMemoryDescriptor`. Every producer traced keeps a bounded
   `mCommandPool[]`; nothing found so far lets one app hold that many bindings on one
   descriptor.
4. **An unbalanced increment.** Not found. The retry path in `AppleAVDDart::mapToDART` was the
   candidate and it is balanced (§4 of the previous revision). Both branches have a matching
   decrement (op-3 arg 0 for the checked branch; op-6 → release helper for the unchecked one).

Until (1) or (3) is answered, the honest severity is: **a kernel hardening defect — an
incomplete bound on a refcount — with no demonstrated memory-safety consequence.**

---

## 7. ARTIFACTS — `analysis/priv24A435/reach/`

| file | purpose |
|---|---|
| `batch_chain.py` / `batch_chain_out.txt` | per-kext ancestor closure + named entries + selector hits |
| `fastxref.py <macho> <va>...` | page-filtered raw xref scan (also bridges indirect hops) |
| `field_sweep.py <off>` | every `add #off`+LSE-atomic and literal-displacement load, collection-wide |
| `xchain.py <macho> <va> [depth]` | upward caller chain; now includes `callees`, `callers_indirect`, `_mat_index` |
| `scan_kexts.py <slot> <div>` | collection-wide vtable-slot call-site scan |
| `ops_at_calls.py <callVA>...` | decode the `w1` op/arg at a call site |
| `gfindvtable.py <macho> <va>` | vtable slot + PAC diversity |
| `gdump.py <macho> <va> <n>` | disassemble any kext |
| `fnident.py`, `callers.py`, `gcallers.py`, `ctx.py`, `dump.py`, `vtdump.py` | helpers |
| `slot88_setmemdesc.txt` | the 120-site producer inventory |
| `dma_op_full.txt` | full disassembly of implementation A |

Known limitation: a forward BFS still misses `IOService` start/probe edges and `__auth_stubs`
hops. "No path found" from a forward walk is not a reachability verdict; the upward walk
(plus the address-materialisation bridge of §2.1) is the reliable direction.

*Line C status: chains closed across four driver types; the unchecked increment is located and
shown to share the field; the only remaining item is demonstrating repeatability at runtime.*
