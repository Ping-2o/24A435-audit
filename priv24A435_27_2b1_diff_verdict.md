# PRIV-24A435 — 27.2b1 (24B5084k) diff: the `_dmaReferences` guard is UNCHANGED

Target A: `/Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.kernel` (27.0 GM 24A435, iPhone17,5)
Target B: `/Users/pauyedin/DirtySlide/ipsw-27.2-beta1/24B5084k__iPhone17,5/kexts/com.apple.kernel`
(27.2 beta 1, 24B5084k, iPhone17,5)

Extraction B: raw kernelcache is already a decompressed Mach-O arm64e (79,446,016 B, 314 load
commands vs 313 in A). `ipsw kernel dec` fails on it (`failed to ASN.1 parse IM4P`) because it is
not IM4P — go straight to `ipsw kernel extract <kc> --all -o kexts`. That yields **301 kexts**;
the one addition over 24A435's 300 is `com.apple.kec.AppleEncryptedArchive`.

---

## 0. HEADLINE

**Apple did not touch the `_dmaReferences` guard in 27.2b1.** The check site, the post-increment
ordering, the `sxth` sign-extension and the signed `cmp #0x4000` are **instruction-for-instruction
identical** between the two builds — relocated, not repaired. Enumerating every atomic on
`descriptor+0x34` gives **4 sites in both builds, exactly 1 bounded and 3 unbounded, with the same
4 roles.** The 27.0 GM fix remains one-branch-only in 27.2b1.

This also settles a question the string-level diff could not: `KEXTS/com.apple.kernel.md` in
blacktop/ipsw-diffs shows **zero** `_dmaReferences` / `IODMACommand` / `IOMemoryDescriptor` /
`dmaCommandOperation` hits in either direction. That is not "removed" — it means *unchanged*, and
since blacktop's per-kext pages are string/symbol-level, a code-only fix would have been invisible
there anyway. The binary confirms which of those two readings is correct.

---

## 1. THE CHECK SITE — identical in both

24A435, inline op-3 increment (`impl A` = `IOMemoryDescriptor::dmaCommandOperation`):

```
0xfffffff00b345530  add      x8, x0, #0x34
0xfffffff00b345534  mov      w9, #1
0xfffffff00b345538  ldaddh   w9, w8, [x8]      ; post-increment, old value -> w8
0xfffffff00b34553c  cbz      w8, ->first-pin
0xfffffff00b345540  sxth     w8, w8            ; sign-extend the 16-bit count
0xfffffff00b345544  cmp      w8, #4, lsl #12   ; signed compare vs #0x4000
0xfffffff00b345548  b.lt     ->work            ; only [0x4000,0x7fff] is caught
0xfffffff00b34554c  adrp/add -> '_dmaReferences overflow @%s:%d'  (line 0xddd = 3549)
```

27.2b1, same role:

```
0xfffffff00b4889a4  add      x8, x0, #0x34
0xfffffff00b4889a8  mov      w9, #1
0xfffffff00b4889ac  ldaddh   w9, w8, [x8]
0xfffffff00b4889b0  cbz      w8, ->first-pin
0xfffffff00b4889b4  sxth     w8, w8
0xfffffff00b4889b8  cmp      w8, #4, lsl #12
0xfffffff00b4889bc  b.lt     ->work
0xfffffff00b4889c0  adrp/add -> '_dmaReferences overflow @%s:%d'  (line 0xdc8 = 3528)
```

Identical sequence, identical encoding of the `ldaddh` (`0x78290108`). The only deltas are the
relocation (`+0x143474` within `__TEXT_EXEC`) and the log **line number, 3549 -> 3528**. That
-21-line shift is consistent with edits elsewhere in `IOMemoryDescriptor.cpp` — the guard itself
was not among them.

## 2. EVERY ATOMIC ON `+0x34` — 4 sites, 1 bounded, in BOTH builds

Word-by-word enumeration of `__TEXT_EXEC.__text` (capstone's generator desyncs on this text; see
§5), matching `add xR, x0, #0x34` immediately feeding an atomic on the same register:

| role | 24A435 | 27.2b1 | sxth | bound |
|---|---|---|---|---|
| inline op-3 **increment** | `0xfffffff00b345538` | `0xfffffff00b4889ac` | yes | **yes** (`cmp #0x4000`) |
| out-of-line **RETAIN** helper | `0xfffffff00b3409dc` | `0xfffffff00b483e78` | ABSENT | **NO BOUND** |
| inline op-3 **decrement** | `0xfffffff00b345750` | `0xfffffff00b488bc4` | ABSENT | **NO BOUND** |
| **32-bit** `ldadd` on a different object | `0xfffffff00ae5448c` | `0xfffffff00af91244` | ABSENT | **NO BOUND** |

`__TEXT_EXEC.__text`: 24A435 `0x8d6fb8`, 27.2b1 `0x8efb6c`. Total sites 4 / bounded 1 / unbounded 3
in **both**.

The RETAIN helper is byte-identical in both builds, which is the important one:

```
0xfffffff00b483e70  add      x8, x0, #0x34
0xfffffff00b483e74  mov      w9, #1
0xfffffff00b483e78  ldaddh   w9, w8, [x8]     ; ++ with NO cmp #0x4000 anywhere
0xfffffff00b483e7c  cbnz     w8, ...          ; (24A435: 0xfffffff00b3409dc, same bytes)
```

The decrement is also identical, including the unsigned `ldrh` gate that the findings note flagged
as the mirror-image weakness:

```
0xfffffff00b488bb4  ldrh     w8, [x0, #0x34]  ; unsigned read
0xfffffff00b488bb8  cbz      w8, ->underflow
0xfffffff00b488bbc  add      x8, x0, #0x34
0xfffffff00b488bc0  mov      w9, #-1
0xfffffff00b488bc4  ldaddh   w9, w8, [x8]
```

So the reachability report's §3.4/§3.5 conclusion — *the bound covers one of the two branches that
increment the counter* — holds unchanged on 27.2b1, and §3.6's remaining item (no runtime
reproducer) is still the only gap.

## 3. NEW LEAD — a `0xface` object with the consumer the findings note was missing

The 4th site is a **different** class, not `IOMemoryDescriptor`: it is gated on a 32-bit magic
(`mov w9, #imm ; movk w9, #0xface, lsl #16 ; cmp w8, w9 ; b.ne`), and it **consumes the
decrement's old value** — which is exactly the "consumer" pattern §6 item 1 of the reachability
note searched for and did not find:

```
0xfffffff00af9123c  add      x9, x0, #0x34
0xfffffff00af91240  mov      w10, #-1
0xfffffff00af91244  ldadd    w10, w9, [x9]    ; 32-bit decrement
0xfffffff00af91248  cmp      w9, #1
0xfffffff00af9124c  b.eq     ...              ; old == 1 -> action
0xfffffff00af91250  cbz      w9, ...          ; old == 0 -> action
```

Same bytes in 24A435 at `0xfffffff00ae5448c`.

**RESOLVED — this is BSD VLAN networking, not an `IOMemoryDescriptor` variant.** The `0xFACEFACE`
magic (`mov w9,#0xface` / `movk w9,#0xface,lsl#16`, `0x529F59C9` / `0x72BF59C9`) appears in exactly
**6 places in the kernel**, all in one cluster around `0xae53xxx–0xae56xxx`, and the strings they
pass to their helper at `0xae53e74` name the subsystem outright:

```
0xfffffff0070750ef  "if_vlan.c"
0xfffffff0070750f9  "ifvlan_release: retain count is 0 @%s:%d"
0xfffffff00707529a  "vlan_parent_signal"
0xfffffff0070753cd  "vlan_parent_link_event"
0xfffffff0070753e4  "vlan_parent_remove_all_vlans"
0xfffffff007075427  "vlan_unconfig"
```

So the object is `struct ifvlan`: magic at `+0x38`, 32-bit retain count at `+0x34`, flags at `+0x20`
(`tst #0xc`, `orr #4`, `orr #0x10`), a key at `+0x10`, a nested list at `+0x18` keyed on a `u16` at
`+0x32`, a second refcount at `+0x44`, and a global registry off `__DATA 0xfffffff00b836000+0xc18`
walked by matching `+0x10`. Objects are held under a `casl` spinlock.

**Verdict: not a lead, and it closes the §6 question in the other direction.** The VLAN retain count
is 32-bit (not wrappable by a 16-bit path), and unlike `_dmaReferences` it *panics* on the analogous
condition — `ldr w8,[x23,#0x34] ; cbz w8, ->panic "ifvlan_release: retain count is 0"` before the
`ldadd`. The DMA counter has the same shape but only *logs*. That contrast is worth one line in the
writeup (it shows the kernel does treat a zero-refcount as fatal elsewhere) but it is not a second
finding, and `+0x34` on `ifvlan` must not be conflated with `+0x34` on `IOMemoryDescriptor` in any
sweep — they are different structures at the same offset.

## 4. REACHABILITY: which chain kexts actually changed

Method: the per-kext pages under `KEXTS/` in the 27.0->27.2 diff, classified by whether
`__TEXT_EXEC.__text` moved. **The README's "Updated (207)" is misleading — most of it is a version
bump with byte-identical sections.**

| chain | kext | version | `__text` | code changed? |
|---|---|---|---|---|
| 1.1 imaging | AppleJPEGDriver | *absent from the updated list entirely* | — | **no** |
| 1.2 video | AppleProResHW | *absent from the updated list entirely* | — | **no** |
| 1.3 SEP | AppleSEPManager | 928.0.2.0.0 -> 928.40.4.0.0 | `0x438e4` both | **no** (only `__const` +0x10) |
| 1.4 storage | IONVMeFamily | 877.0.7.0.0 -> 877.40.5.0.0 | `0x5bff8` -> `0x5ae74` (**-0x1184**) | **yes** |
| — | IOSurface | 402.8.0.0.0 -> 403.1.0.0.0 | +0x18, **2 functions** | **yes**, surgical |
| — | IODARTFamily | 373.0.1.0.0 -> 373.40.3.0.0 | `0x1380c` both | **no** |
| — | ApplePIODMA | 764.0.0.0.0 -> 764.40.3.0.0 | `0x3f94` both | **no** |
| — | IOMobileGraphicsFamily(-DCP) | 700.50.97.13.0 -> 700.50.104.1.0 | +0x110 / -0x4 | yes, but **not** on the DART-map entry |
| — | AppleAVE2 | 913.43.1.0.0 -> 913.48.1.0.0 | +0x20, 4 functions | **yes** |

Consequences for reachability on 24A435:

* **JPEG (sel 1/3/5), ProRes (sel 3) and SEPManager are byte-identical in 27.2** — the three chains
  closed in the reachability note transfer directly, and the absence of any Apple change on them
  means nothing in 27.2 invalidates them.
* **IODARTFamily and ApplePIODMA are byte-identical** — the DART layer under the producers is
  unchanged, so the producer->`setMemoryDescriptor` mapping stands.
* **IONVMeFamily is the one chain that really moved** (-0x1184 text, 3588 -> 3555 functions, the
  assert `"fSanitizeInProgress == true"` **removed**, 5 new `"Sanitize Status *"` strings). That is
  the largest producer in the map (44 bind sites) and its selectors are the entitlement-gated ones —
  re-verify it against 27.2 before relying on it. `UnifiedPipeline2::dart_map_mdesc_gated` is **not**
  in the DCP changed-function list, so the graphics producer entry is unchanged.

## 5. HARVEST — thin. One lead downgraded, one negative result, one string-level change

Bottom line before the detail: **this diff does not hand over a usable bug on 24A435.** The two
candidates it produced both dissolved on inspection — AVE2 is a refactor, and the `+0x34` object is
BSD VLAN code. The only genuinely harvested item is a *string* change in IONVMeFamily.

**AppleAVE2 — a scalar became an indexed array. CORRECTED, and downgraded.**

The fetched diff summary rendered the new string as `sMBStats[m]`; reading `__TEXT.__cstring` out of
both binaries gives the actual change (`kext_cstring_diff.py`):

```
-  "pInfo->sBufPFSet.sMBStats.iAddr != 0"      ; a SCALAR member, no index
+  "pInfo->sBufPFSet.saMBStats[m].iAddr != 0"  ; an ARRAY member, indexed by m
+  "... invalid MB/CTU stats firmware buffer %p %d %lld %p %lld | %d"   ; new %d = the index
```

Note **`saMBStats`**, not `sMBStats` — one character, and it changes the reading. The member was
renamed and changed from a single struct to an indexed array, with per-element validation and the
index added to the log. `__TEXT.__cstring` grew exactly +9 bytes (0x4804a -> 0x48053) and
`__TEXT_EXEC.__text` +0x20 in both this extraction and blacktop's.

The code around the assert is near-identical between the two builds — same `mov w0,#4 ; bl <alloc>`,
same surrounding loads, assert line 0x608 -> 0x60a. `AVE_CHM_SetDataInfo_FwBuf` grew only 28 bytes
(23044 -> 23072).

**Assessment: this reads as a scalar -> array refactor that carries its own validation, not as a fix
for a missing bound.** On 24A435 there was one `sMBStats`; there is no element to leave unchecked.
The honest severity is "worth a look", not "candidate bug", and it should not be listed as a
harvested fix until the index's provenance in 27.2b1 is traced (`m` is computed where, and bounded
where). If `m` in 27.2b1 is itself unbounded, that would be a new 27.2 issue, not a 24A435 one —
opposite direction. To settle it: find the `iAddr != 0` *test* site (the windows above are the
assert-failure blocks, not the tests) and walk back to where `m` is formed.

Still true: the DPB/ref-frame macro arguments changed `16,16` -> `16,15`, but both evaluate to the
same bound (`max(16,15)+1 = 17`), so that part is inert either way.

**IONVMeFamily — an assert removed, not added.** `"fSanitizeInProgress == true"` disappears while
5 sanitize-status strings appear. An assert that was *removed* is a lead in the other direction:
the invariant it encoded was either relaxed or made unreachable. Lower confidence than the AVE2
item.

**Unchanged in this diff:** no new bound, string, or symbol relating to `_dmaReferences` anywhere.
`com.apple.kernel` did grow (+249 functions, +362 cstrings) but the additions are coredump/panic
(`kdp_core.c`, `coredump_encryption`, `com.apple.private.coredump-encryption-key`), `iptap.c` /
`pktap_build_mbuf_header`, and speculative-page VM accounting — plus `ucoredump` **removed**, which
bears on the separate `kernel_ucoredump.md` workstream.

## 6. STATUS

**Proven, byte-exact:**
1. The `_dmaReferences overflow` guard added in 27.0 GM is **unchanged in 27.2b1** — same `ldaddh`
   -> `sxth` -> signed `cmp #0x4000` -> `b.lt`, relocated by `+0x143474` only.
2. 4 atomic sites on `descriptor+0x34`, **1 bounded / 3 unbounded, in both builds**, same roles.
3. The unbounded RETAIN helper and the unsigned-`ldrh`-gated decrement are byte-identical in both.
4. The overflow log line moved 3549 -> 3528; the underflow string still has 2 code xrefs in both.
5. 27.2b1's kext collection is 301 vs 300; the addition is `com.apple.kec.AppleEncryptedArchive`.

**Still not proven** (unchanged from the reachability note): that the counter is drivable to
`0x8000`, and any memory-safety consequence. The severity remains **a kernel hardening defect — an
incomplete bound on a refcount** — and it is now *also* confirmed unfixed in 27.2b1.

**Reportable:** the defect is present in 27.0 GM (24A435), 27.0 release (24A437, per
`24A437_diff_verdict.md`) **and 27.2 beta 1 (24B5084k)**. That is a stronger disclosure position
than before: not a stale GM-only finding.

## 7. ARTIFACTS

| file | purpose |
|---|---|
| `analysis/priv24A435/dmafix_cmp.py` | Mach-O parse + `adrp+add` xref to the log strings + window disasm, both kernels |
| `analysis/priv24A435/dmaref_sites.py` | enumerate every atomic on `+0x34`, classify bounded/unbounded |
| `analysis/priv24A435/dmafix_around.py` | dump an instruction window around any VA in a kernelcache |
| `analysis/priv24A435/kext_cstring_diff.py` | **authoritative** `__TEXT.__cstring` diff between two kexts |
| `analysis/priv24A435/strxref.py` | find a string in a kext and disassemble every `adrp+add` xref to it |

**Do not trust the fetched diff markdown as evidence.** `KEXTS/*.md` is useful as a *map* of where to
look, but the content arrives through a summariser that silently drops characters — it rendered
`saMBStats[m]` as `sMBStats[m]`, which inverted the meaning of the AVE2 change and sent this pass
down a wrong path for several rounds. With both kext collections extracted locally, every claim must
be re-derived from the binaries (`kext_cstring_diff.py` for strings, `strxref.py` for the code). The
section-size tables in the markdown were accurate and matched the local extraction exactly, so use
those to decide *which* kexts to open — not to conclude what changed.

Gotchas encoded in these (each cost a debugging round):
* `section_64.offset` is a **u32** — `struct.unpack_from("<QQQ", ...)` silently yields an empty
  slice and a "0 instructions" scan.
* capstone's `disasm()` generator **stops at the first undecodable word** in a 9 MB text — decode
  word-by-word, and pre-filter on encoding masks (`ldadd` family `(w & 0x3FC00000) == 0x38000000`,
  ADD imm `(w & 0x7F000000) == 0x11000000`, SUBS imm `... == 0x71000000`).
* `X0` is `ARM64_REG_X0`, **not** `0` — comparing `operand.reg == 0` matches nothing.
* `cmp w8, #4, lsl #12` is **SUBS**, not SBFM; match it on `op_str` (`"#0x4000"` or `"#4, lsl #12"`).

---

## 8. PRODUCER SWEEP + §3.6 RESOLVED (class names of the A/B vtable groups)

### 8.1 The real diff is 72 kexts, not 207

`producer_survey.py` diffs all 300 common kexts straight from the binaries (text + cstring
sizes). **72 changed**; the other 228 are version-bump-only with byte-identical text and cstrings.
The markdown's "Updated (207)" is not a code-change count.

Biggest *producer* movements (text delta):

| kext | text | cstr |
|---|---|---|
| `com.apple.driver.IOACIPCFamily` | **+0x6b744** | +0x1db7 |
| `com.apple.driver.AppleConvergedIPCBBControl` | **+0x37898** | +0xe2e |
| `com.apple.kernel` | +0x18bb4 | +0x43a0 |
| `com.apple.driver.AppleH16ANEInterface` | +0x7a24 | +0x399 |
| `com.apple.iokit.IONVMeFamily` | **-0x11ac** | +0x67 |
| `com.apple.driver.AppleMobileDispH17P-DCP` | +0xbb8 | +0x5ab |
| `com.apple.driver.RTBuddy` | +0x948 | +0x840 |
| `com.apple.driver.AppleM2ScalerCSCDriver` | +0x6e8 | +0x1f1 |

Note both `IOACIPCFamily` and `AppleConvergedIPCBBControl` carry `acipc-skip-entitlement` alongside
"user client missing access entitlement" — a skip flag on a producer's entitlement check is worth a
look on its own. Neither has a found selector, so they are not app-reachable today.

### 8.2 Only FOUR of the 37 producer kexts are app-reachable

Cross-referencing `reach/batch_chain_out.txt` (which found selectors for only 4 kexts) with the
binary diff and the gating strings:

| chain | text delta | userclient | selectors | class-specific entitlement |
|---|---|---|---|---|
| **AppleJPEGDriver** | **+0x0** | `AppleJPEGDriverUserClient` | 1, 3, 5 | **none** (only generic `IOUserClientEntitlements`) |
| AppleProResHW | +0x0 | `AppleProResUserClient` | 3 | `com.apple.private.proreshw` |
| AppleSEPManager | +0x0 | `AppleSEPUserClient` | 1 | `com.apple.private.applesepmanager.allow` |
| IONVMeFamily | **-0x11ac** | `AppleNVMeUserClient`, `AppleNVMeSMARTUserClient` | 1, 2, 6, 7 | NVMe EAN / FWNamespace / Namespace Device (several) |

**AppleJPEGDriver is the reachability winner** and it is now proven rather than asserted: its code is
byte-identical between 24A435 and 27.2b1, it is the only one of the four with no class-specific
entitlement string, and it carries three selectors into the pin. The other 33 producer kexts have
producers but no userclient entry point found — they are kernel-internal.

### 8.3 §3.6 RESOLVED — A = IOGeneralMemoryDescriptor, B = IOBufferMemoryDescriptor

Chained-fixup encoding, cracked against the known-good JPEG dispatch table:

```
stored qword = <32 bits fixup metadata> : <low32 = target_VA - 0x7004000>
0x8050bcad_0201eda4  ->  0x7004000 + 0x0201eda4 = 0xfffffff009022da4   (JPEG sel 1)
```

Verifying the whole table at `0xfffffff008078860` decodes sel 0..4 to
`0x9022d98 / da4 / dd8 / de4 / e18` — byte-exact agreement with the reachability note, which also
validates the note's table extraction independently.

Searching the kernel for the two `dmaCommandOperation` implementations under that encoding gives:

* **impl A (checked op-3 path): 4 vtables** — `0xfffffff007e47f00`, `0x7e480d8`, `0x7e7f8e8`, `0x7e7faf0`
* **impl B (UNCHECKED op-5 path): 5 vtables** — `0xfffffff007e46758`, `0x7e47888`, `0x7e47bd8`, `0x7e47da8`, `0x7e7f708`

**A = 4 vtables, B = 5 vtables — exactly the split in the reachability note §3.1, now confirmed
independently.** All nine are at **slot 18 (`0x90`)**, as expected.

Class identification: the code that installs B's vtable `0xfffffff007e47da8` loads the string

```
'Attempting to free IOBMD with page allocated flag @%s:%d'
```

**IOBMD = `IOBufferMemoryDescriptor`** — so the **unchecked** branch is the
`IOBufferMemoryDescriptor` family. A's group carries `IOGMD: not wired for the IODMACommand`
(note §3.1), i.e. **`IOGeneralMemoryDescriptor`**, and takes the **checked** path.

The installer also does `ldrh w22, [x20, #0x34]` — an *unsigned* 16-bit read of the same `+0x34`
field, consistent with the decrement's `ldrh` gate.

**Consequence:** the branch an app hits depends on which descriptor class the driver hands to
`IODMACommand::setMemoryDescriptor`. A user-supplied address range yields an
`IOGeneralMemoryDescriptor` → checked path (subject to the signedness hole). A driver-internal
`IOBufferMemoryDescriptor` → **the unchecked path, where the 27.0 GM fix does not apply at all.**
Deciding which class the JPEG chain passes is now a bounded, answerable question — trace what
`AppleJPEGDart::mapMemoryDescriptor`'s caller supplies.

### 8.4 Honest status of "100% reachability"

* Reachability **to the increment**: closed, four chains, JPEG strongest (§8.2).
* **Which branch** a given chain takes: resolved at the class level (§8.3); per-chain attribution
  still to do.
* **The `0x8000` drive**: still not demonstrated. Requires ~32,768 outstanding references on one
  descriptor, or an unbalanced increment. No reproducer exists. This is the one thing that static
  analysis cannot supply, and it remains the honest blocker on severity.

### 8.5 New artifacts

| file | purpose |
|---|---|
| `producer_survey.py` | per-kext text/cstring diff over both collections + UC classes + gating strings |
| `producer_survey_out.txt` | its output (the 72-changed table and all 39 producer detail blocks) |
| `vtable_hunt.py` | find vtables holding a function VA, with the cracked chained-fixup decoder |
| `vtable_hunt_out.txt` | the nine A/B vtables and the IOBMD class string |

`producer_survey.py`'s dispatch-table column is **broken** — it looks for plain VAs, which do not
exist. Reuse `vtable_hunt.decode_ptr` to fix it if that column is wanted.

---

## 9. SANDBOXED-APP REACHABILITY — status, one correction, and the exact blockers

### 9.1 Ghidra MCP is not usable in this environment

Installed the extension (`/Users/pauyedin/tools/ghidra-mcp/target/GhidraMCP-7.0.0.zip` →
`~/.ghidra/.ghidra_12.1.3_PUBLIC/Extensions/GhidraMCP`). `ghidraRun` then fails:

```
#  SIGBUS (0xa) at pc=... CodeHeap::allocate(unsigned long)+0x15c
#  JRE version: (21.0.12.1)
ERROR: Failed to find a supported JDK.
```

Reproduced twice — inside the sandbox and with the sandbox disabled and `JAVA_HOME` pinned to the
bundled JRE. JDK 21.0.12 and 25.0.4 are both installed; the crash is in the JVM's code-cache
allocation, not in JDK selection. `hs_err_pid75423/75424/75426.log` are in `~/`. The MCP bridge
process runs (`bridge-mcp-ghidra`) but `127.0.0.1:8089` refuses connections, so `list_instances`
returns empty and no Ghidra tools are callable.

**Nothing below depends on Ghidra.** The chained-fixup decoder, the vtable hunt and the class
identification in §8 were all done with the capstone tooling, and they are byte-exact and
reproducible. If Ghidra is wanted for a future pass it needs the JVM issue solved first (worth
trying `-Xint` / a reduced `ReservedCodeCacheSize` via the launcher's JAVA_OPTS, or a different
JDK) — that is a tooling problem, not an analysis one.

### 9.2 The client side: VideoToolbox does NOT open the userclient

`VideoToolbox` (a framework linked into app processes) links
`/System/Library/PrivateFrameworks/AppleJPEG.framework/AppleJPEG`, and defines
`AppleJPEGVideoDecoder` — a VTDecoder subclass with `_StartSession`, `_DecodeFrame`, `_Finalize`,
`_Invalidate`, `_SetProperty`, `_kAppleJPEGVideoDecoderVTable`.

But it contains **0** occurrences of `AppleJPEGDriverUserClient` (only 7 `IOService`, 2 `IOKit`).
So the IOKit open does **not** happen in VideoToolbox. It happens inside `AppleJPEG.framework`,
which is not in the kernelcache and not in the local extraction.

### 9.3 RESOLVED — AppleJPEGDriver is the LEAST-gated chain (an intermediate claim of mine was wrong)

**Correction to a correction.** An earlier revision of this section asserted that AppleJPEGDriver
*is* entitlement-checked, because its binary contains the string `IOUserClientEntitlements`. That
inference was wrong, and it was the same class of error §7 warns about: reasoning from the *presence
of a string* without checking whether the thing it names actually exists. Reading the Info.plists
(§10) settles it in the opposite direction.

What is actually true:

* The JPEG kext has the *machinery*. At `0xfffffff00902271c` (wrapper) → `0xfffffff00902280c`:
  `x0 = self; x1 = "IOUserClientEntitlements"; blraa self->vtable[0xc8]` — it reads that property.
  The wrapper has **0 direct `bl` callers**; it is a virtual method reached by vtable, the same
  indirect pattern as `dmaCommandOperation`.
* But **no kext in either kernelcache declares `IOUserClientEntitlements`** (§10.2), so at runtime
  that read returns NULL.
* And AppleJPEGDriver hardcodes **no** `com.apple.private.*` entitlement, unlike every other chain
  (§10.3).

So the honest basis for the ranking is: JPEG has the entitlement *plumbing* but no configured gate
and no hardcoded entitlement, while ProRes, SEPManager and IONVMeFamily each hardcode theirs. §8.2's
ordering stands — now on evidence rather than on the absence of a string.

The residual unknown is what the JPEG caller does with a NULL result (allow vs deny). Given that
ImageIO must work for every app and the property is declared nowhere, "allow" is the only
self-consistent reading — but it is not yet disassembled down to that branch.

### 9.4 What is required to close "100% from a sandboxed app"

Three artifacts, none of which are in the kernelcache:

| # | artifact | what it settles |
|---|---|---|
| a | `/System/Library/PrivateFrameworks/AppleJPEG.framework/AppleJPEG` | confirms it opens the `AppleJPEGDriver` service, and whether that open is in-process for an app |
| b | `AppleJPEGDriver.kext/Info.plist` (`IOUserClientEntitlements` value) | the exact entitlement the userclient demands |
| c | the app sandbox profile (`container` / the per-app profile) | whether `iokit-user-client-class` for the JPEG userclient is granted, or the entitlement is one a normal app holds |

(a) comes from the dyld shared cache (same extraction route as `VideoToolbox`); (b) from the IPSW
filesystem or the IORegistry property; (c) from the IPSW filesystem
`/System/Library/Sandbox/Profiles/`.

### 9.5 What is NOT blocked

* The **kernel side is closed and byte-verified** — four chains, selectors resolved, code unchanged
  in 27.2b1.
* The **A/B branch question is answered at class level**: A (`IOGeneralMemoryDescriptor`) takes the
  checked op-3 path; B (`IOBufferMemoryDescriptor`) takes the **unchecked** op-5 path where the GM
  fix does not apply.
* What remains is *permission*, not *reachability within the kernel*. That is a documentation
  problem with three specific missing files, not an analysis dead end.

---

## 10. THE KEXT INFO.PLISTS ARE IN THE KERNELCACHE — gating settled

### 10.1 New capability: read every kext's Info.plist without the IPSW filesystem

`__PRELINK_INFO` in the raw kernelcache is populated (0x270000 bytes) and contains a plist whose
`_PrelinkInfoDictionary` key holds **every kext's Info.plist**: **318 entries for 24A435, 319 for
27.2b1** (the +1 is `com.apple.kec.AppleEncryptedArchive`, consistent with §0).

```python
pl = plistlib.loads(blob[blob.find(b"<?xml"): blob.find(b"</plist>") + 8])
entries = pl["_PrelinkInfoDictionary"]          # 318 / 319 dicts
```

`kext_plist_survey.py` does this for both builds. **This removes the need for the IPSW filesystem for
artifact (b) in §9.4** — the entitlement question is answerable from what is already on disk.

### 10.2 No kext declares `IOUserClientEntitlements` — in either build

```
24A435  kexts declaring IOUserClientEntitlements: 0   (of 318)
27.2b1  kexts declaring IOUserClientEntitlements: 0   (of 319)
```

Not one, at the kext level or inside any `IOKitPersonalities` entry. The generic IOKit gate is
therefore unconfigured across the entire kernel collection, and any `getProperty` of that key —
including the JPEG kext's at `0xfffffff00902280c` — returns NULL at runtime.

Also worth noting: the personalities carry **no `IOUserClientClass`** for the chains except
IONVMeFamily's `AppleEmbeddedNVMeController` → `AppleNVMeUpdateUC`. The userclient classes
(`AppleJPEGDriverUserClient`, `AppleProResUserClient`, `AppleSEPUserClient`) are not declared in the
plists either, so the UC class is chosen by the driver's `newUserClient` override, not by the plist.

### 10.3 The discriminator: hardcoded entitlement strings

Since the plist mechanism is unused, the only gate is whatever each driver checks in code. Grepping
the binaries for `com.apple.*` entitlement strings:

| chain | hardcoded entitlements |
|---|---|
| **AppleJPEGDriver** | **none** |
| AppleProResHW | `com.apple.private.proreshw` |
| AppleSEPManager | `com.apple.private.applesepmanager.allow`, `com.apple.System.sep.art`, `com.apple.applesepos.storage.stats` |
| IONVMeFamily | **7**: `com.apple.AppleNVMeEAN.allow`, `.AppleNVMeFWNamespace.allow`, `.AppleNVMeNamespaceDevice.allow`, `.AppleNVMeSanitize.allow`, `.AppleNVMeSideBar.allow`, `com.apple.nvmefwupdate.allow`, `com.apple.nvmetunnel.allow` |

**AppleJPEGDriver is the only one of the four that names no entitlement at all.** That is the
strongest available evidence for the §8.2 ranking, and it is binary-derived rather than inferred.

### 10.4 Updated §9.4 blocker list

| # | artifact | status |
|---|---|---|
| a | `AppleJPEG.framework` (from the DSC) | still needed — confirms it opens the `AppleJPEGDriver` service and whether in-process |
| b | `AppleJPEGDriver.kext/Info.plist` entitlement | **NO LONGER NEEDED** — answered in §10.2/§10.3 |
| c | app sandbox profile (`/System/Library/Sandbox/Profiles/`) | still needed — the last permission gate |

So the ask shrinks from three files to two, and the remaining one that matters most is the sandbox
profile: a sandboxed app must be granted `iokit-user-client-class` for the JPEG userclient. That is
the only thing left between this analysis and a complete "reachable from a sandboxed app" claim.

---

## 11. CLIENT SIDE FOUND — `JPEGH1.videodecoder`, and the pin has exactly one entry

### 11.1 The client chain, end to end

`ipsw dyld str` over the DSC resolves who names the driver:

```
0x2bda2a999: "AppleJPEGDriver"           image=JPEGH1.videodecoder
0x2bde83bcc: "AppleJPEGDriver"           image=JPEGH1.videoencoder
0x1a67cba1c: "AppleJPEGDriver"           image=CMPhoto
0x1afa6be67: "AppleJPEGDriver"           image=libMobileGestalt.dylib
0x180a22d8f: "AppleJPEGDriverUserClient" image=CoreFoundation
```

`AppleJPEG.framework` and `VideoToolbox` contain **no** reference to the driver — so the plug-in is
the client, not the framework. Extracted with `ipsw dyld extract`, `JPEGH1.videodecoder` (92 KB,
`__text` = 0x2ea0) does, at `0x2bda29b98`:

```
adrp/add x0, "AppleJPEGDriver"
bl       IOServiceMatching
mov      x1, x0 ; mov x0, x19
bl       IOServiceGetMatchingService      ; x19 = kIOMainPortDefault
str      w0, [service_slot]               ; the AppleJPEGDriver service
...
adrp/add x1, "AppleJPEGNumCores"
bl       IORegistryEntryCreateCFProperty  ; reads the core count
...
bl       IOServiceOpen
```

and then calls the userclient — **exactly two `IOConnectCallStructMethod` sites in the whole image,
both with selector 7**:

```
0x2bda29d28  mov  w8, #0xda0 ; str x8,[sp,#8]   ; outSize = 3488
0x2bda29d38  mov  w1, #7                        ; <<< selector 7
0x2bda29d3c  mov  x2, x20                       ; input struct
0x2bda29d40  mov  w3, #0xda0                    ; input size 3488
0x2bda29d44  mov  x4, x19                       ; output struct
0x2bda29d48  bl   IOConnectCallStructMethod
```

So the client-side chain is **closed and verified**: VideoToolbox plug-in → `IOServiceMatching` →
`IOServiceOpen` → `IOConnectCallStructMethod`. Artifact (a) from §9.4 is now answered.

### 11.2 The full selector → implementation map (table @ `0xfffffff008078860`, 40-byte stride)

| sel | thunk | implementation |
|---|---|---|
| 0 | `0xfffffff009022d98` | `0xfffffff00901717c` |
| 1 | `0xfffffff009022da4` | `0xfffffff009018830` |
| 2 | `0xfffffff009022dd8` | `0xfffffff009017188` |
| 3 | `0xfffffff009022de4` | `0xfffffff009019ad0` |
| 4 | `0xfffffff009022e18` | `0xfffffff009019ee4` |
| **5** | `0xfffffff009022e4c` | **`0xfffffff009019334` = `AppleJPEGDriver::queue_io`** |
| 6 | `0xfffffff009022e80` | `0xfffffff00901a9e8` |
| **7** | `0xfffffff009022eb4` | **`0xfffffff00901a348`** ← what the client actually sends |
| 8 | `0xfffffff009022ee8` | `0xfffffff0090165e4` |
| 9 | `0xfffffff009022f18` | `0xfffffff00901667c` |

**Sel 5 → `queue_io` confirms the reachability note's chain entry exactly.** Each thunk is the same
shape: `x4 = x0; x0 = [x0+0xe0]` (the driver object); `cbz x0 -> 0xe00002bc (kIOReturnNotReady)`;
then `b <impl>`.

### 11.3 The pin has exactly ONE entry point — this is the useful new constraint

```
mapMemoryDescriptor (0x901b1cc) callers: 4
    0xfffffff0090172c0  0xfffffff009017364  0xfffffff009017900  0xfffffff0090179a4
    (all in the 0x90171xx-0x90179xx buffer-setup family: setupBuffersForCoding_gated,
     doRestOfBufferSetupFor{Decode,Encode}_gated)

queue_io_gated (0x9018c0c) callers: 0        <- reached only through IOCommandGate (indirect)
queue_io       (0x9019334) callers: 2
    0xfffffff009022e70  = table-1 sel 5 thunk
    0xfffffff0090230b8  = the SECOND table's thunk
```

**Every route to the `_dmaReferences` increment funnels through `queue_io` (`0x9019334`), and
`queue_io` has only two callers — both of them externalMethod thunks.** That is a tight, verifiable
reachability bottleneck, and it is much stronger than "one of the selectors reaches the pin".

### 11.4 The tension that must be resolved before claiming the chain

**The one real client found sends selector 7, and sel 7's implementation (`0x901a348`) does not call
`queue_io`, `queue_io_gated`, or `mapMemoryDescriptor`.** By §11.3, `queue_io` is the sole entry to
the pin, so **the VideoToolbox plug-in's sel-7 call is not the pin-driving call** — on the evidence
so far it looks like a capability/init call (it allocates a request object at `0x901a3cc` and copies
fields in).

Two candidate explanations, both cheap to test:

1. **There is more than one client.** `JPEGH1.videoencoder`, `CMPhoto` and `libMobileGestalt.dylib`
   also name the driver; one of them may send sel 5. I only disassembled `JPEGH1.videodecoder`.
2. **There is a second dispatch table.** The thunks at `0x9023094 / 0x90230b8 / 0x90230e0 /
   0x902310c / 0x9023130…` are a second set with the same shape, mapping to the same
   implementations at *different* indices (`0x9019ee4`, **`queue_io`**, `0x901a9e8`, `0x901a348`,
   `0x903c658`…). So "which selector reaches the pin" is **per-table**, and the note's numbering is
   only table 1's. If the client connects through a UC whose table is this second one, its selector 7
   could map to something else entirely.

Explanation 2 is the more interesting one and it also explains the §10.2 observation that the
userclient classes are not declared in the plists: multiple tables imply multiple UC classes, with
the mapping decided by whichever `newUserClient` override ran.

### 11.5 Revised status of "100% from a sandboxed app"

| element | status |
|---|---|
| kernel side: increment, bound, unchecked branch | **closed, byte-verified** (§1-§3) |
| which branch (A vs B) | **resolved at class level** (§8.3) |
| entitlement gate | **resolved — JPEG names none** (§10.2/§10.3) |
| client that opens the driver | **found and disassembled** (§11.1) |
| selector the client sends | **sel 7 — but sel 7 is not on the pin path** (§11.4) |
| app sandbox profile (`iokit-user-client-class` grant) | **still missing** — the last permission gate |

So the honest position is: the client exists and is disassembled, the pin bottleneck is now a
single function, and **the remaining work is to match a client selector to `queue_io`** — plus the
sandbox profile. I have *not* closed the claim, and §11.4 explains exactly why.

### 11.6 New artifacts

| file | purpose |
|---|---|
| `dsc_out/JPEGH1.videodecoder` | the client, extracted from the DSC |
| `dsc_out/JPEGH1.videoencoder`, `dsc_out/CMPhoto`, `dsc_out/AppleJPEG` | the other candidate clients |
| `dsc_out/JPEGH1_dec.txt` | full annotated disassembly of the client's `__text` (2984 insns) |

Useful tooling note: `ipsw dyld extract <DSC> <name> -o <dir>` works with a bare image name;
`ipsw dyld str <DSC> <string>` resolves *which image* contains a string — that is what located the
client. `ipsw dyld disass <DSC> --image X` OOMs on a 92 KB image; disassemble by `--vaddr` instead,
or dump with capstone as done here.

---

## 12. THE TABLE NUMBERING IS CONFIRMED — and the client does NOT drive the pin

### 12.1 The dispatch table, verified by struct sizes

Locating each thunk's record in `__DATA_CONST.__const` (decoded with the §8.3 fixup decoder) gives
records of `{ptr_enc, u32 × 8}` at 40-byte stride, base `0xfffffff008078860`:

| selector | record address | index = (rec − base)/40 | fields after ptr |
|---|---|---|---|
| 0 | `0xfffffff008078860` | 0 | `(0, 0, 0, 0, 0, 0, 0, 0)` |
| **5** | `0xfffffff008078928` | **5** | `(0, 4096, 0, 4096, 0, 0, 0, 0)` |
| **7** | `0xfffffff008078978` | **7** | `(0, **3488**, 0, **3488**, 1, 0, 0, 0)` |

Two independent confirmations that the note's numbering is right:

1. sel 5's record carries `structIn = structOut = 4096` — exactly what the reachability note says
   for sel 5.
2. sel 7's record carries `structIn = structOut = **3488**`, and the real client
   (`JPEGH1.videodecoder`, §11.1) calls `IOConnectCallStructMethod` with `0xda0 = 3488` for both
   input and output. **The client's struct size matches the table record exactly**, which confirms
   both the table base and that the client's selector 7 is the one it intends.

So the base is `0x8078860`, index 7 is selector 7, and the note's `sel 5 → 4096` is correct.

### 12.2 CORRECTED — the pin entry is `queue_io_gated`, dispatched by SIX selectors

An earlier revision of this section concluded "the client cannot reach the pin", reasoning from
`queue_io`'s two-caller set. **That was wrong, and the error was tracking the wrong function.**
`queue_io` (`0x9019334`) is only the *ungated wrapper* used by selector 5. The actual shared entry is
**`queue_io_gated` (`0x9018c0c`)**, which is not called directly at all — it is dispatched through an
`IOCommandGate`. Materialising its address with `adrp+add` (the note's own §2.1 trick) gives **six**
sites, one in each of six different selector implementations:

| site | enclosing function | selector implementation |
|---|---|---|
| `0xfffffff009018a64` | `0xfffffff009018834` | **sel 1** (`0x9018830`) |
| `0xfffffff0090197dc` | `0xfffffff009019338` | **sel 5** = `queue_io` (`0x9019334`) |
| `0xfffffff009019d50` | `0xfffffff009019ad4` | **sel 3** (`0x9019ad0`) |
| `0xfffffff00901a280` | `0xfffffff009019ee8` | **sel 4** (`0x9019ee4`) |
| **`0xfffffff00901a814`** | **`0xfffffff00901a34c`** | **sel 7** (`0x901a348`) ← the client's selector |
| `0xfffffff00901ada0` | `0xfffffff00901a9ec` | **sel 6** (`0x901a9e8`) |

And the dispatch in the sel-7 implementation is unambiguous:

```
0xfffffff00901a7f8  ldr   x0, [x22, #0xb8]      ; the IOCommandGate
0xfffffff00901a7fc  ldr   x16, [x0]
0xfffffff00901a808  autda x16, x17
0xfffffff00901a80c  ldr   x9, [x16, #0xe8]!     ; vtable slot 0xe8 = runAction
0xfffffff00901a814  adrp  x16, #0xfffffff009018000
0xfffffff00901a818  add   x16, x16, #0xc0c     ; x16 = 0xfffffff009018c0c = queue_io_gated
0xfffffff00901a820  pacia x16, x17
0xfffffff00901a824  mov   x1, x16               ; arg1 = the action
```

That is `IOCommandGate::runAction(queue_io_gated, request)`.

So **six different userclient selectors — 1, 3, 4, 5, 6 and 7 — all funnel into `queue_io_gated`**,
which is the true bottleneck. `queue_io` is just one of the six wrappers, and it also runs the gate.
The `mapMemoryDescriptor` caller set (4 callers, all in the `0x90171xx`–`0x90179xx` buffer-setup
family under `queue_io_gated`) is unchanged and still correct.

### 12.3 What the two real clients actually send

| client | selector | implementation | reaches `queue_io`? |
|---|---|---|---|
| `JPEGH1.videodecoder` | **7** (×2 sites) | `0xfffffff00901a348` | **no** |
| `JPEGH1.videoencoder` | **6** (×1 site) | `0xfffffff00901a9e8` | **no** |
| `CMPhoto` | — uses a different API (no `IOConnectCallStructMethod`) | — | — |
| `libMobileGestalt.dylib` | — mentions the name, makes **no** userclient call | — | — |

**Every image in the DSC that names the driver has now been tested.** `JPEGH1.videodecoder` (7) and
`JPEGH1.videoencoder` (6) are the only two that open the userclient at all; `CMPhoto` and
`libMobileGestalt.dylib` merely mention the name. Neither sends selector 5 — **and that no longer
matters**, because §12.2 shows both 6 and 7 dispatch `queue_io_gated` directly.

### 12.4 The chain is CLOSED from the client

```
sandboxed app
  -> VideoToolbox  -> JPEGH1.videodecoder   (in-process plug-in; §11.1)
  -> IOServiceMatching("AppleJPEGDriver") -> IOServiceGetMatchingService -> IOServiceOpen
  -> IOConnectCallStructMethod(selector 7, in 3488, out 3488)      [struct sizes match the
                                                                    table record exactly, §12.1]
  -> AppleJPEGDriverUserClient::externalMethod -> thunk 0x9022eb4
  -> 0xfffffff00901a348
  -> IOCommandGate::runAction(queue_io_gated)                      [§12.2, site 0x901a814]
  -> queue_io_gated 0xfffffff009018c0c
  -> setupBuffersForCoding_gated / doRestOfBufferSetupFor{Decode,Encode}_gated
  -> AppleJPEGDart::mapMemoryDescriptor 0xfffffff00902b1cc          [4 callers, all in this family]
  -> IODMACommand::setMemoryDescriptor -> dmaCommandOperation
  -> _dmaReferences increment   (checked op-3 if cmd->[0x40]==0, UNCHECKED op-5 otherwise, §3)
```

**Every kernel-side link is byte-verified, and the client-side link is now verified too.** Combined
with §10 (AppleJPEGDriver hardcodes no entitlement, and no kext declares `IOUserClientEntitlements`),
the only remaining unknown is the app sandbox profile.

### 12.5 What is still missing — one item

A sandboxed app still has to be permitted to open the `AppleJPEGDriver` userclient, i.e. the app's
sandbox profile must grant `iokit-user-client-class` for it. That file lives in the IPSW filesystem
(`/System/Library/Sandbox/Profiles/`), is not in the kernelcache, and cannot be derived from what is
on disk here. **That is now the single outstanding item** — everything else in the chain, from the
public API to the counter increment, is established at the binary level.

### 12.6 Method note — why §12.2 was wrong the first time

I searched for callers of `queue_io`
(the function the *note* named as the chain entry) and, finding only two thunk callers, concluded the
client could not reach it. The correct move — the one the note itself documents in its §2.1 — is to
follow the **`IOCommandGate`**: the gated function is never called directly, so it has **zero** direct
callers, and a caller-based argument about it is meaningless. You must materialise its address with
`adrp+add` and enumerate *those* sites. Doing so immediately produced six, one per selector.

Corollary for any future chain work in this kext: **when a function has zero direct callers, do not
read that as unreachable** — check for `adrp+add` materialisation (gate actions, `IOTimer` callbacks,
thread continuations, ops tables) before drawing any conclusion.

---

## 13. THE `iokit-user-client-class` GRANT — FOUND

### 13.1 Where the profiles actually live

The 24A435 restore IPSW is on disk at
`/Users/pauyedin/Downloads/iPhone17,5_27.0_24A435_Restore.ipsw`. `ipsw extract --files --pattern`
pulls files out of the filesystem DMGs:

```
ipsw extract --files --pattern '.*\.sb$' -o ipsw_all <ipsw>
```

That yields **40 `.sb` files** — all of them *framework* or *XPC-service* profiles (`AuthKit
framework.sb`, `ReportCrashService.sb`, `IMTransferAgent.sb`, …). **`container.sb`, `application.sb`,
`baseline.sb` and the `com.apple.WebKit.*` profiles are NOT on disk** — `/System/Library/Sandbox/
Profiles/` contains exactly one file (`com.apple.doorsd.sb`). The profiles that matter are
**compiled into `com.apple.security.sandbox`**.

### 13.2 The grant is present in the compiled profiles

`com.apple.security.sandbox` (24A435) contains:

```
"iokit-user-client-class"       4 occurrences
"AppleJPEGDriverUserClient"     5 occurrences  @0x1e0c7 0x1f478 0x2029f 0x9819b 0x1a603b
"AppleJPEGDriver"               7 occurrences  (+ @0x9bc43, @0x1a8613 as an iokit-open service name)
```

So **`AppleJPEGDriverUserClient` appears inside `iokit-user-client-class` grant lists in the compiled
sandbox profiles.** The grant exists. It clusters in three groups:

| group | offsets | character |
|---|---|---|
| Apple-Internal / test | `0x1e0c7`, `0x1f478`, `0x2029f`, `0x9819b` | adjacent strings are `com.apple.dt.XCTest`, `SWECI-Tests-iOS.xctest`, `AudioToolboxTests_iOS-Runner`, `com.apple.CITests.xctrunner`, `com.apple.pencilkit.TestingHarness`, `AppleInternal`, `usr/local/bin`, `com.Apple.RgbIrTestApp` — **internal test profiles**, alongside `AGXDeviceUserClient`, `IOSurfaceRootUserClient`, `H11ANEInDirectPathClient`, `IOAccelContext2`, `AppleKeyStoreUserClient`, `RootDomainUserClient` |
| Accessory / CarPlay | `0x1a603b` | adjacent: `com.apple.carkit.service`, `com.apple.CarPlayApp.service`, `com.apple.airplay.endpoint.xpc`, `com.apple.iapd.xpc`, `AccessibilityUIServer`, `com.apple.linkd.registry`, `AppleSPUHIDDriverUserClient`, `accessoryd` |
| **WebKit** | `0x9bc43` | pool run: `com_apple_driver_FairPlayIOKit` / **`AppleJPEGDriver`** / `IOSurfaceRoot` / `H1xANELoadBalancer` / `AppleVirtIONeuralEngineDevice` / `H11ANEIn` / `ANEHintClientSession`, then `com.apple.webkit.extension.mach`, `com.apple.WebKit.GPU`, `com.apple.WebKit.Model`, `com.apple.WebKit.Networking`, **`com.apple.WebKit.WebContent`**, `com.apple.ImageIOXPCService`; markers `com.apple.security.ts.webkit-client` (`0x9b982`) and `com.apple.webkit.extension.iokit` (`0x9b9ab`) just before |

**CORRECTION — I got the WebKit row wrong on first write, and it is the load-bearing row.**
`AppleJPEGDriverUserClient` (the **userclient class**) does **NOT** occur in the WebKit region. It
occurs exactly 5 times: `0x1e0c7`, `0x1f478`, `0x2029f` (Apple-Internal/XCTest), `0x9819b` (mixed
internal), `0x1a603b` (Accessory/CarPlay). The WebKit region contains only **`AppleJPEGDriver`**, the
*service / registry-entry class* name — grouped with `IOSurfaceRoot`, `H1xANELoadBalancer`,
`AppleVirtIONeuralEngineDevice`, `H11ANEIn`, which are likewise bare class names with no
`UserClient` suffix. `UserClient`-suffixed names in the WebKit region are only
`AppleVideoToolboxParavirtualizationUserClient`, `ANEClientHintsUserClient` and
`AppleVirtIONeuralEngineDeviceUserClient` — not the JPEG one.

So the accurate split is:

* **`iokit-user-client-class` → `AppleJPEGDriverUserClient`**: granted by **Apple-Internal/XCTest**
  profiles and by the **Accessory/CarPlay** profile group. **Not** by WebKit, and not by any
  app-container profile visible here.
* **`AppleJPEGDriver` as a service / registry-entry class**: granted by the **WebKit** group
  (alongside `IOSurfaceRoot`, ANE and framebuffer classes), with the `com.apple.webkit.extension.iokit`
  sandbox extension available to it.

Which of the two filters actually gates `IOServiceOpen` — the service class, the userclient class, or
both — is a sandbox-semantics question I have **not** resolved, and the two readings point opposite
ways for reachability. That is the honest state.

### 13.3 Precision, and what would make it exact

The sandbox kext stores profiles as compiled bytecode over a shared string pool, so **adjacency in
the pool is strong evidence of co-membership but is not proof of it.** What is certain:

* the grant exists, and it is `iokit-user-client-class` → `AppleJPEGDriverUserClient`;
* the WebKit markers (`com.apple.security.ts.webkit-client`, `com.apple.webkit.extension.iokit`,
  `com.apple.WebKit.{GPU,WebContent}`) are in the same pool region as the `AppleJPEGDriver` grants.

What would make it exact: decode the compiled profile bytecode in `com.apple.security.sandbox` and
walk the `iokit-user-client-class` op's operand list per profile, or obtain a build whose
`com.apple.WebKit.*` profiles ship as text `.sb` files. The ipsw-diffs pages cannot help here — they
are *diffs*, and this grant did not change between 27.0 and 27.2, so it never appears in them.

### 13.4 Reachability status after §13

| element | status |
|---|---|
| counter, bound, unchecked branch | **closed, byte-verified** |
| branch selection (A vs B) | **resolved at class level** |
| entitlement gate | **none** — JPEG hardcodes no entitlement; 0/318 kexts declare `IOUserClientEntitlements` |
| client that opens the driver | **found, disassembled** (`JPEGH1.videodecoder`, sel 7) |
| selector → pin | **closed** — sel 7 → `IOCommandGate::runAction(queue_io_gated)` |
| **sandbox grant** | **located, but NOT in an app-facing profile** — `iokit-user-client-class` → `AppleJPEGDriverUserClient` appears only in Apple-Internal/XCTest and Accessory/CarPlay profiles; the WebKit group grants the *service* name instead (§13.2) |

Every kernel-side link in the chain is evidenced. The **permission** link is now the open question,
and it did not resolve the way I first reported it.

**Consequence for how this is framed — and it is the opposite of what I said an hour ago:**

* If `IOServiceOpen` on this driver is gated by **`iokit-user-client-class`**, then the only profiles
  carrying that grant are **Apple-Internal test** and **Accessory/CarPlay** — so a normal sandboxed
  app, and WebKit, would **not** be able to open the userclient, and the chain would be reachable
  only from CarPlay/Accessory processes (a much narrower and less interesting surface).
* If it is gated by the **service / registry-entry class**, then the **WebKit** group has it
  (`AppleJPEGDriver` alongside `IOSurfaceRoot`, ANE and framebuffer classes, plus
  `com.apple.webkit.extension.iokit`), and the entry point is a WebKit sandboxed process reached via
  attacker-controlled web content.

I do **not** know which of the two applies, and I am not going to pick one to make the story tidy.
Resolving it is the next concrete task (§13.3), and it is a sandbox-semantics question, not a
disassembly one.

---

## 14. RESOLVED — the grant, verbatim, and the process that holds it

### 14.1 The op table settles the semantics

`com.apple.security.sandbox`'s op-name table (`__TEXT.__cstring`, `0x1f247d`-`0x1f24e5`) contains
**two distinct IOKit ops**:

```
iokit*
iokit-get-properties
iokit-issue-extension
iokit-open*                 <- group
iokit-open-user-client      <- opening a USERCLIENT
iokit-open-service          <- opening a SERVICE
iokit-set-properties
```

So opening a userclient and opening a service are separately gated. **Opening
`AppleJPEGDriverUserClient` is the `iokit-open` / userclient path, whose filter is
`iokit-user-client-class` — not the service name.** That confirms §13.2's correction: the WebKit
group's bare `AppleJPEGDriver` (a service/registry-entry class) is **not** sufficient to open the
userclient.

### 14.2 The grant, verbatim

`grep` over the 40 extracted text profiles finds **exactly one** that grants it —
`System/Library/PrivateFrameworks/AccessibilitySharedUISupport.framework/com.apple.accessibility.AccessibilityOnboarding.sb`:

```scheme
(allow iokit-open
    (iokit-user-client-class "AGXDeviceUserClient")
    (iokit-user-client-class "IOHIDParamUserClient")
    (iokit-user-client-class "AppleJPEGDriverUserClient")
    (iokit-user-client-class "IOSurfaceRootUserClient"))
```

That is the answer: **`(allow iokit-open (iokit-user-client-class "AppleJPEGDriverUserClient"))`**,
in a real shipping profile, in a framework profile (so it applies to processes loading
`AccessibilitySharedUISupport.framework`). The other seven `.sb` files that grant
`iokit-user-client-class` grant `AppleKeyStoreUserClient`, `ApplePMGRUserClient`, `AppleNVMeEANUC`,
`BootPolicyUserClient`, `IGAccelDevice`, `AGXDeviceUserClient` — not the JPEG one.

This also matches the kext string pool: `AccessibilityUIServer` sits immediately before
`AppleVirtIONeuralEngineDeviceUserClient` / `AppleJPEGDriverUserClient` at `0x1a603b`, the offset I
had loosely filed under "CarPlay/Accessory".

### 14.3 The full chain, and the honest caveat on who can enter it

```
sandboxed process (holds the grant)
 → VideoToolbox → JPEGH1.videodecoder            [in-process plug-in]
 → IOServiceMatching("AppleJPEGDriver") → IOServiceOpen → IOConnectCallStructMethod(sel 7, 3488/3488)
 → thunk 0x9022eb4 → 0x901a348
 → IOCommandGate::runAction(queue_io_gated)
 → queue_io_gated 0x9018c0c
 → setupBuffersForCoding_gated / doRestOfBufferSetupFor{Decode,Encode}_gated
 → AppleJPEGDart::mapMemoryDescriptor 0x901b2cc
 → IODMACommand::setMemoryDescriptor → dmaCommandOperation
 → _dmaReferences increment   (checked op-3 if cmd->[0x40]==0, UNCHECKED op-5 otherwise)
```

Every link is now evidenced, and the permission link has an exact, citable form.

**The caveat, stated plainly:** the grantee is **`AccessibilityOnboarding`**, not a generic app
container and not WebKit. Across the 40 text profiles on the filesystem, that is the only profile
granting the userclient class; the compiled-in profiles additionally carry it in the
Apple-Internal/XCTest group. So:

* **Reachable from a sandboxed process — YES**, with the grant named.
* **Reachable from an arbitrary sandboxed app — NOT established**, and on this evidence it looks
  false. A normal app's `container` profile is not among the profiles carrying the UC class, and
  the WebKit group carries the *service* class instead.

If the report is to claim an app-facing entry, the remaining task is to show either (a) that the
client process is `AccessibilityOnboarding`-class rather than app-hosted, or (b) that some client
process holds the **entitlement** `com.apple.security.iokit-user-client-class` with
`AppleJPEGDriverUserClient` in its signature — the entitlement route bypasses the profile, and it is
the one path not yet checked. That needs a signed binary from the IPSW, not the kernelcache.

### 14.4 Method note — the two traps that cost the most time

1. **`AppleJPEGDriver` and `AppleJPEGDriverUserClient` are different filters.** Conflating them
   produced a wrong, load-bearing conclusion (§13.2). Grep the *exact* filter string.
2. **The `container`/`application`/`baseline`/WebKit profiles are compiled into
   `com.apple.security.sandbox`**, not on the filesystem — but *framework* and *XPC-service* profiles
   are plain text `.sb` files in the IPSW, and those are greppable in one command:
   `ipsw extract --files --pattern '.*\.sb$' <ipsw>`, then grep for the class name. That is what
   finally answered this after four wrong turns through the kernelcache and the diff markdown.

---

## 15. CHAIN COMPLETE — the gate is an ENTITLEMENT on `ImageIOXPCService`

### 15.1 The grant mechanism is entitlement-based, not profile-based

Extracted from the IPSW filesystem **with its code signature intact**:

```
ipsw extract --files --pattern '.*ImageIOXPCService.*' -o ipsw_clients <ipsw>
codesign -d --entitlements :- .../ImageIO.framework/XPCServices/ImageIOXPCService.xpc/ImageIOXPCService
```

```
com.apple.security.iokit-user-client-class   <array>
        H11ANEInDirectPathClient
        AppleJPEGDriverUserClient          <-- the grant
        IOSurfaceRootUserClient
        IOSurfaceAcceleratorClient
        IOGPUDeviceUserClient
com.apple.videotoolbox.decode-in-process         <true/>
com.apple.videotoolbox.hardwarevideodecoder      <true/>
com.apple.private.sandbox.profile:embedded       <string>autobox</string>
platform-application                             <true/>
```

Three things fall out of this at once:

1. **`com.apple.security.iokit-user-client-class` carrying `AppleJPEGDriverUserClient`** is the
   permission link. It is an **entitlement**, which is why grepping sandbox profiles was
   inconclusive — a process can hold this without any profile rule (§14.2's `AccessibilityOnboarding`
   profile is the profile-based form of the same grant; `ImageIOXPCService` is the entitlement form).
2. **`com.apple.videotoolbox.decode-in-process = true`** — the VideoToolbox plug-in runs **inside
   `ImageIOXPCService`**, so it is `ImageIOXPCService`'s sandbox that governs, and it holds the grant.
   That closes the "which process opens the userclient" question that `JPEGH1.videodecoder`'s own
   binary could not answer.
3. **`com.apple.videotoolbox.hardwarevideodecoder = true`** — hardware decode is enabled, i.e. the
   path to the hardware JPEG block is intended.

### 15.2 The complete chain

```
sandboxed app  /  attacker-controlled web content
 -> ImageIO  (public framework; no special entitlement needed to use it)
 -> XPC to com.apple.ImageIOXPCService
      entitlements: iokit-user-client-class [AppleJPEGDriverUserClient, IOSurfaceRootUserClient, ...]
                    videotoolbox.decode-in-process = true
                    videotoolbox.hardwarevideodecoder = true
                    sandbox.profile:embedded = autobox,  platform-application
 -> loads JPEGH1.videodecoder in-process
 -> IOServiceMatching("AppleJPEGDriver") -> IOServiceGetMatchingService -> IOServiceOpen
 -> IOConnectCallStructMethod(selector 7, in 3488, out 3488)
 -> thunk 0xfffffff009022eb4 -> 0xfffffff00901a348
 -> IOCommandGate::runAction(queue_io_gated)
 -> queue_io_gated 0xfffffff009018c0c
 -> setupBuffersForCoding_gated / doRestOfBufferSetupFor{Decode,Encode}_gated
 -> AppleJPEGDart::mapMemoryDescriptor 0xfffffff00902b1cc
 -> IODMACommand::setMemoryDescriptor -> dmaCommandOperation
 -> _dmaReferences increment   (checked op-3 if cmd->[0x40]==0, UNCHECKED op-5 otherwise)
```

**Every link is now evidenced, and the entry point is attacker-reachable**: any process that asks
ImageIO to decode an attacker-supplied JPEG reaches `ImageIOXPCService`. The input is a file format
an attacker fully controls.

### 15.3 Final status

| link | evidence |
|---|---|
| counter, bound, unchecked branch | byte-verified; unchanged in 27.2b1 (§1–§3) |
| branch selection (A vs B) | `IOGeneralMemoryDescriptor` checked / `IOBufferMemoryDescriptor` UNCHECKED (§8.3) |
| driver entitlement gate | none — JPEG hardcodes no entitlement; 0/318 kexts declare `IOUserClientEntitlements` (§10) |
| client that opens the driver | `JPEGH1.videodecoder`, selector 7 (§11) |
| selector → pin | sel 7 → `IOCommandGate::runAction(queue_io_gated)` (§12.2) |
| **sandbox permission** | **`com.apple.security.iokit-user-client-class` = `AppleJPEGDriverUserClient` on `ImageIOXPCService`, with `decode-in-process = true` (§15.1)** |

The chain from an app-reachable, attacker-controlled input down to the `_dmaReferences` increment is
complete. What remains is **not** a reachability question: it is the empirical `0x8000` drive
(~32,768 outstanding references on one descriptor, or an unbalanced increment), which no static
analysis can settle and which is still the honest blocker on severity.

---

## 16. THE `0x8000` DRIVE — an unbalanced increment exists in the JPEG chain

The reachability note's §6 item 4 recorded "**An unbalanced increment — not found.**" It searched the
*retry* path in `AppleAVDDart::mapToDART`. It did not examine `AppleJPEGDart::mapMemoryDescriptor`'s
**error** paths. Doing so finds one.

### 16.1 What `mapMemoryDescriptor` does

`AppleJPEGDart::mapMemoryDescriptor` (`0xfffffff00902b1cc`) takes `(self, IOMemoryDescriptor *desc,
uint32_t nseg, IODMACommand **outCmd, IOPhysicalAddress *outDva, s_debug *)`. It:

1. validates the arguments (`0x902b204`–`0x902b278`), then
2. **creates a fresh `IODMACommand`** via the call at `0x902b31c`, then
3. **pins the descriptor** at `0x902b34c`:

```
0xfffffff00902b34c  ldr   x8, [x16, #0x88]!     ; vtable slot 0x88 = setMemoryDescriptor
0xfffffff00902b354  mov   x1, x24               ; the IOMemoryDescriptor
0xfffffff00902b358  mov   w2, #1                ; cache = true
0xfffffff00902b360  blraa x8, x16               ; >>> THE INCREMENT <<<
0xfffffff00902b364  mov   x24, x0               ; return code
```

Because `_dmaReferences` lives on the **descriptor**, not the command, **every call on the same
descriptor increments the same counter** — and because a *new* command is created each time, repeated
calls do not reuse a single command's state.

### 16.2 The error path leaks the command

```
0xfffffff00902b37c  cbz   w24, #0xfffffff00902b458   ; pin OK -> success path
0xfffffff00902b380  ...   (log)                       ; pin FAILED -> falls through
0xfffffff00902b3ac  b     #0xfffffff00902b4d8        ; -> common exit
...
0xfffffff00902b458  (success path: further setup, then a virtual call on the command)
0xfffffff00902b488  mov   x0, x25
0xfffffff00902b490  blraa x8, x16
0xfffffff00902b498  cbz   w0, #0xfffffff00902b4cc
0xfffffff00902b49c  ...   (log)
0xfffffff00902b4c8  b     #0xfffffff00902b4d8
0xfffffff00902b4cc  ldr   x8, [sp, #0x10]
0xfffffff00902b4d0  str   x8, [x20]                   ; *outDva = dva
0xfffffff00902b4d4  str   x25, [x19]                  ; *outCmd = the IODMACommand
0xfffffff00902b4d8  mov   x0, x24
0xfffffff00902b4dc  ...   epilogue
0xfffffff00902b4f8  retab
```

**The command (`x25`) is handed to the caller at `0x902b4d4` on the success path only.** Every error
path — the pin failure at `0x902b380`, the argument-validation failures at `0x902b3b0` / `0x902b3e8` /
`0x902b420`, and the post-pin failure at `0x902b49c` — jumps straight to the common exit at
`0x902b4d8` with **no release call on `x25`** anywhere between the failure branch and the `retab`.
There is no `vtable[0x28]` (release) and no `release()` on the command in any of those paths.

### 16.3 Why that is an unbalanced increment

Combine §16.2 with the note's own §3: the `ldaddh` increment executes **before** the bound check, so
it stands even when `setMemoryDescriptor` returns an error. Therefore:

* a call whose pin **fails** still leaves `_dmaReferences` **+1**, and
* the command that would have carried the matching decrement is **leaked**, so the `-1` never comes.

**Net: +1 per failed `mapMemoryDescriptor` call, permanently.** That is the unbalanced increment the
note's §6 said it could not find, and it is reachable through the now-closed JPEG chain (§15.2) — the
descriptor is the one the caller supplies, so *repeat* calls on the same descriptor accumulate on the
same counter.

### 16.4 What this changes, and what it does not

**Changes:** the drive to `0x8000` no longer requires ~32,768 *concurrent* outstanding references on
one descriptor — which the note correctly identified as the hard part and could not find a way to
reach. A **leak** only requires 32,768 *sequential* failed calls on one descriptor. That is a
qualitatively easier target, and it is the difference between "needs a contrived concurrency
primitive" and "needs a loop".

**Does not change:** it is still not demonstrated at runtime. What is proven is the *mechanism* — a
leaking error path plus an unconditional post-increment. Confirming that the counter actually climbs
still needs either a runtime test or a careful reading of whether `setMemoryDescriptor`'s own failure
handling already undoes the increment internally (i.e. whether the `ldaddh` can be paired with a
decrement inside `IODMACommand` on its own error path). That last point is the one thing that could
still invalidate this, and it is checkable statically in `com.apple.kernel` — the same
`dmaref_sites.py` enumeration from §2 applies.

**Confidence:** the leaked-command observation is high (directly readable from the control flow). The
unbalanced-increment conclusion is **medium until `IODMACommand::setMemoryDescriptor`'s own error
handling is checked for a compensating decrement** — that is the next call, not a runtime test.

### 16.5 The kernel side — the increment is not compensated on the error path

`IODMACommand::setMemoryDescriptor` (`0xfffffff00b337ad8`), tail:

```
0xfffffff00b337c84  ldr   x8, [x19, #0x40]      ; cmd->[0x40]
0xfffffff00b337c88  cmp   x8, #0
0xfffffff00b337c8c  cset  w8, eq
0xfffffff00b337c94  strb  w8, [x9, #0x7e]
0xfffffff00b337ca0  cbz   w8, #0xfffffff00b337ccc    ; cmd->[0x40] != 0 -> skip the pin
0xfffffff00b337ca4  ldr   x16, [x20]                 ; x20 = the IOMemoryDescriptor
0xfffffff00b337cac  ldr   x8, [x16, #0x90]!          ; descriptor slot 0x90
0xfffffff00b337cb4  mov   w1, #1
0xfffffff00b337cb8  movk  w1, #0x300, lsl #16        ; w1 = 0x03000001 = op 3 / arg 1 = PIN
0xfffffff00b337cbc  mov   x2, x19
0xfffffff00b337cc8  blraa x8, x16                    ; >>> THE INCREMENT <<<
0xfffffff00b337ccc  cbz   w22, #0xfffffff00b337d34
0xfffffff00b337cfc  blraa x8, x16                    ; cmd->slot0xa0(0,0,1,1)
0xfffffff00b337d00  cbz   w0, #0xfffffff00b337d38    ; success -> return 0
0xfffffff00b337d18  mov   x20, x0                    ; save the error
0xfffffff00b337d1c  mov   x0, x19                    ; x19 = the COMMAND (not the descriptor)
0xfffffff00b337d20  mov   w1, #1
0xfffffff00b337d28  blraa x8, x16                    ; cmd->slot0x90(w1 = 1)
0xfffffff00b337d2c  mov   x0, x20
0xfffffff00b337d38  ... epilogue, retab
```

Two things matter here:

1. **The pin is `descriptor->dmaCommandOperation(w1 = 0x03000001, x2 = cmd)`** — the `0x03000001`
   encoding is exactly the pin form the reachability note §2 derived (`op 3 / arg 1`), and it is issued
   at `0xb337cc8`, i.e. inside the `cmd->[0x40] == 0` branch. That independently confirms §3.4's
   gate table and pins the increment to this one call.

2. **The error path does not issue the unpin.** After the pin, a later failure calls
   **`cmd->slot0x90(w1 = 1)`** — note `x0 = x19`, the *command*, whereas the pin used `x0 = x20`, the
   *descriptor*. So this is a command method, and its `w1 = 1` is **not** the unpin encoding
   (`0x03000000`). On this evidence there is **no compensating decrement** for the pin on
   `setMemoryDescriptor`'s error path.

**Confidence:** the pin site and the "no `0x03000000` on the error path" observation are high — both
read directly off the control flow. The residual doubt is that `cmd->slot0x90(w1 = 1)` is a virtual
call whose target is not statically fixed, so it cannot be excluded that it *internally* unpins.
Resolving that means resolving `IODMACommand`'s own vtable slot `0x90` — a bounded read, but a
different one from the `+0x34` enumeration, since it is a command method rather than a descriptor
atomic.

### 16.5b CORRECTION — that virtual call is the teardown, and it DOES unpin

Resolving `IODMACommand`'s vtable settles it, and it **invalidates the "no compensating decrement"
half of §16.5**. Finding the vtable containing `setMemoryDescriptor`:

```
vtable_hunt.py <kernel> 0xfffffff00b337ad8  ->  vtable base 0xfffffff007e46518, slot 17 (offset 0x88)
```

which matches the JPEG call site's `cmd->vtable[0x88]` exactly, and slot 20 (`0xa0`) decodes to
`0xfffffff00b33732c` — `IODMACommand::dmaCommandOperation`, matching the note's §3.4. So this is
`IODMACommand`'s real vtable. **Slot 18 (`0x90`) = `0xfffffff00b337a00`**, and it is the teardown:

```
0xfffffff00b337a6c  ldr   x8, [x19, #0x70]
0xfffffff00b337a70  ldrb  w8, [x8, #0x7e]      ; the flag setMemoryDescriptor wrote
0xfffffff00b337a74  cbz   w8, #0xfffffff00b337aa4
0xfffffff00b337a78  ldr   x16, [x0]            ; x0 = [x19,#0x48] = cmd->fMemory (the descriptor)
0xfffffff00b337a88  ldr   x8, [x16, #0x90]!    ; descriptor slot 0x90
0xfffffff00b337a8c  mov   w1, #0x3000000       ; 0x03000000 = op 3 / arg 0 = UNPIN
0xfffffff00b337a9c  blraa x8, x16              ; >>> THE DECREMENT <<<
```

So `cmd->slot0x90(...)` is the teardown that **unpins**, gated on the same `[0x70]->[0x7e]` flag that
`setMemoryDescriptor` sets to `(cmd->[0x40] == 0)`. The two are consistent: pin issued ⇒ flag set ⇒
teardown unpins; pin skipped ⇒ flag clear ⇒ teardown skips.

**Therefore `setMemoryDescriptor`'s error path IS balanced** — it calls that teardown at
`0xb337d28` before returning. My §16.5 claim that "the error path does not issue the unpin" was
**wrong**; the unpin is one virtual hop away, and I stopped reading too early.

### 16.6 The unbalanced increment — corrected mechanism, same conclusion

The imbalance is **not** in `setMemoryDescriptor`. It is in the **JPEG caller**, at the *second*
failure point, and the distinction matters:

```
0x902b360  blraa x8, x16          ; setMemoryDescriptor  -> PIN  (success => w24 == 0)
0x902b37c  cbz   w24, #0x902b458  ; pin FAILED -> error path
0x902b458  (success path)
0x902b46c  bl    0x902b0e0        ; further setup
0x902b470  ldr   x16, [x25]       ; x25 = the IODMACommand
0x902b478  ldr   x8, [x16, #0xb8]! ; cmd->vtable[0xb8]  (= 0xfffffff00b3366fc)
0x902b490  blraa  x8, x16
0x902b498  cbz   w0, #0x902b4cc   ; OK -> store outputs
0x902b49c  (error log)
0x902b4c8  b     #0x902b4d8       ; -> retab, command x25 LEAKED
0x902b4cc  ldr   x8, [sp, #0x10]
0x902b4d0  str   x8, [x20]
0x902b4d4  str   x25, [x19]       ; *outCmd = the command  <-- SUCCESS PATH ONLY
0x902b4d8  ... retab
```

Two failure points, and they behave differently:

* **Pin failure** (`0x902b37c`): `setMemoryDescriptor` has already torn the command down internally
  (§16.5b), so the descriptor is **balanced**. Only the command object leaks — a memory leak.
* **Post-pin failure** (`0x902b49c`): the pin **succeeded** (so `setMemoryDescriptor` did *not* tear
  down), and then `cmd->vtable[0xb8]` failed. The function returns **without releasing `x25`**, so the
  command's teardown — and therefore the unpin — **never runs**.

**Net: +1 on `_dmaReferences` per failed `mapMemoryDescriptor` call at the post-pin failure point,
permanently.** That is the unbalanced increment.

### 16.7 Where the `0x8000` drive stands

| element | status |
|---|---|
| JPEG `mapMemoryDescriptor` leaks `x25` on every error path | high — `str x25,[x19]` on the success path only |
| `setMemoryDescriptor` compensates on its own error path | **YES — corrected** (§16.5b); its error path calls `cmd->slot0x90` = teardown = unpin |
| post-pin failure leaves the pin outstanding | high — pin succeeded, command leaked, teardown never runs |
| net | **+1 per failed call at `0x902b49c`** |

**What this changes:** the note's §6 item 4 ("an unbalanced increment — not found") is now **found**,
in the JPEG chain rather than the AVD retry path it searched. The `0x8000` drive no longer requires
~32,768 *concurrent* references — the thing the note rightly called unreachable. It requires 32,768
*sequential failed calls on one descriptor*, i.e. a loop.

**What it does not change:** still not demonstrated at runtime. And the trigger for the post-pin
failure is `cmd->vtable[0xb8]` (`0xfffffff00b3366fc`) returning non-zero — **what makes that fail, and
whether a client can force it, is the next question**, not the refcount bookkeeping. That is the last
static unknown, and it is a bounded read of one function.

### 16.8 The trigger — `cmd->slot0xb8` is a prepare/segment-walk with validation

`0xfffffff00b3366fc` is a thin wrapper that tail-branches to `0xfffffff00b335fa4` with `w1 = 0x80`,
`x2` = `0xfffffff00b336748` and `x3` = `cmd->[0x50]`. The validator at `0xfffffff00b336748` is what can
return non-zero:

```
0xfffffff00b33677c  mov   w19, #0x2e1
0xfffffff00b336780  movk  w19, #0xe000, lsl #16    ; 0xe00002e1
0xfffffff00b336784  ldr   w9, [x1, #0x5c]          ; a request field
0xfffffff00b336788  sub   w10, w9, #1
0xfffffff00b33678c  cmp   w10, #0x3e
0xfffffff00b336790  b.hi  #0xfffffff00b3367c4     ; (field-1) > 0x3e  -> ERROR
0xfffffff00b336794  add   x10, x3, x2
0xfffffff00b336798  sub   x10, x10, #1
0xfffffff00b33679c  lsr   x9, x10, x9
0xfffffff00b3367a0  cbz   x9, #0xfffffff00b3367c4 ; size does not fit -> ERROR
0xfffffff00b3367a4  ldr   x9, [x1, #0x70]
0xfffffff00b3367a8  ldrb  w9, [x9, #0x7b]          ; a flag
0xfffffff00b3367ac  cbz   w9, #0xfffffff00b3367bc
0xfffffff00b3367b0  mov   w20, #0x2e1             ; flag set -> ERROR 0xe00002e1
```

So the post-pin failure fires when the segment request is malformed: a request field at `[x1,#0x5c]`
outside `1..0x3f`, a size that does not fit the requested shift, or the flag at `[x1,#0x70]->[0x7b]`
being set. **The request buffer (`x1`) comes from `mapMemoryDescriptor`'s caller, and the JPEG userclient
selector 7 takes a 3488-byte client-supplied struct** — so this is plausibly client-influenceable. That
is the last thing to confirm, and it is the difference between "a leak that needs a malformed request"
and "a leak a sandboxed client can drive at will".

---

## 17. IS THIS AN LPE? NO — and here is exactly what is missing

Asked directly, the answer is **no**. What has been built is **reachability to a defective refcount
increment** — the *precondition* work for an LPE, not an LPE. The distinction matters and should not be
smoothed over.

### 17.1 What IS established

| # | claim | evidence |
|---|---|---|
| 1 | a sandboxed process can reach the `_dmaReferences` increment | §11–§15, end to end |
| 2 | the permission gate is an entitlement on `ImageIOXPCService` (`decode-in-process = true`) | §15.1 |
| 3 | the increment's guard is defective: signed compare, post-increment, 1 of 4 sites bounded | §1–§3 |
| 4 | the defect is unchanged in 27.2b1 | §0 |
| 5 | a leak path exists (post-pin failure leaves the pin outstanding) | §16.6 |

### 17.2 What is NOT established — the four LPE gaps, all still open

1. **No wrap demonstrated.** `_dmaReferences` has never been shown to reach `0x8000`. §16.6 supplies a
   *mechanism* (a leak makes the drive sequential rather than concurrent), but the trigger — a
   client-influenced malformed segment request reaching `[x1,#0x5c]` / `[x1,#0x70]->[0x7b]` — is
   **unconfirmed**, and no drive has been run.
2. **No consumer.** Swept the `IOMemoryDescriptor`/`IODMACommand` cluster for reads of the field:
   `0x34` is not 8- or 4-divisible, so only 2-byte loads can hit it, giving **13 `ldrh` sites**. The
   one inspected (`0xb3347d4`) reads the value and passes it to a reporting path
   (`bl 0xfffffff00b438dc0`) — **no branch on it**. The note's §6 item 1 therefore stands: nothing
   frees, tears down, or short-circuits on the value.
3. **No memory-safety consequence.** No UAF, no out-of-bounds, nothing. The note's own verdict —
   *"a kernel hardening defect — an incomplete bound on a refcount — with no demonstrated memory-safety
   consequence"* — is unchanged by everything found since.
4. **No privilege boundary crossed.** No escalation is demonstrated at any point.

### 17.3 The framing that should go in any report

The reachability chain's **acting** process is `ImageIOXPCService` — a system service carrying
`platform-application` and the `iokit-user-client-class` entitlement. So the shape is *"a sandboxed,
non-privileged app influences a privileged system service to drive a kernel refcount"*, which is the
correct shape for a sandbox-escape primitive. But **influence is not escalation**, and no escalation is
shown. The honest one-line summary is:

> Reachable, defective, unfixed — and with no demonstrated consequence.

Everything in §1–§16 is real and byte-verified. None of it is an LPE, and none of it should be
presented as one. What it *is* is the reachability and defect half of an LPE report, done properly,
with the consequence half still missing.

---

## 18. THE CONSUMER — FOUND (the note's §6 item 1 is resolved)

The note's §6 item 1 said: *"A consumer that treats `_dmaReferences == 0` as 'no DMA in flight' and
acts on it. Not found. … If such a consumer exists it is outside that cluster and would be found by
sweeping for **reads** of `descriptor+0x34` rather than atomics."*

**That sweep was run. The consumer is at `0xfffffff00b343bdc`** — inside the cluster, in
`IOMemoryDescriptor.cpp`.

### 18.1 The site

```
0xfffffff00b343bdc  ldrh  w8, [x0, #0x34]      ; w8 = _dmaReferences
0xfffffff00b343be0  cbnz  w8, #0xfffffff00b343db0   ; != 0  -> the assert block
0xfffffff00b343be4  ldrb  w8, [x20, #0x2d]
0xfffffff00b343be8  tbz   w8, #1, #0xfffffff00b343c20
0xfffffff00b343bec  ldr   x8, [x20]
0xfffffff00b343bf0  ldp   x4, x5, [x20, #0x10]
...
0xfffffff00b343c04  bl    #0xfffffff00b340a44      ; the out-of-line RELEASE helper
```

and the branch target:

```
0xfffffff00b343db0  adrp  x8, #0xfffffff0070c1000
0xfffffff00b343db4  add   x8, x8, #0xdb9            ; "IOMemoryDescriptor.cpp"
0xfffffff00b343db8  mov   w9, #0x14d3               ; line 5331
0xfffffff00b343dc0  adrp  x0, #0xfffffff0070c1000
0xfffffff00b343dc4  add   x0, x0, #0xf8c            ; the assert text
0xfffffff00b343dc8  bl    #0xfffffff00b41f6bc      ; the assert/log helper
```

The string at `0xfffffff0070c1f8c` is:

```
'complete() while dma active @%s:%d'
```

**That is exactly the string the findings note §1 already located in `IODMACommand.cpp`** — so the
site is `IODMACommand`'s completion path asserting that no DMA references are outstanding, i.e.
`assert(_dmaReferences == 0)` at `IOMemoryDescriptor.cpp:5331`, immediately before it calls the
release helper.

### 18.2 What is proven, and what is not

**Proven:** a read of `_dmaReferences` that branches on the value, in the completion path, with an
explicit diagnostic naming the condition. The note's §6 item 1 ("no consumer") is therefore **no
longer accurate** — a consumer exists, and it is in the cluster.

**Not yet resolved — and it decides severity:** whether the log is *terminal* for that path.
`0xb41f6bc` is a thin varargs wrapper around `0xfffffff00aba5090`; it has **thousands of callers with
live code following the call** (spot-checked: `sxtw x1, w23` after one, function prologues after
others), which says it **returns** — i.e. a logger, not a `panic`. But the assert block at
`0xb343db0` is immediately followed by an unrelated function prologue at `0xb343dcc` with no `b` in
between, which is the shape of a block whose callee is assumed non-returning.

Those two readings cannot both be right, and they mean opposite things:

* **If the log is non-terminal** → the code *reports* "complete() while dma active" and then
  **proceeds to complete anyway**. That is the use-after-free shape the note originally hypothesised
  and later withdrew: `complete()` running with DMA still mapped.
* **If the log is terminal** → it is a hard guard, and the condition is a panic (DoS) rather than
  memory corruption.

Resolving it is a bounded read of `0xfffffff00aba5090`'s return behaviour, and it is now the single
most consequential open question in this document. **I am not going to guess it**, because guessing
here is the difference between a hardening note and a UAF claim.

### 18.3 What this does and does not change about §17

§17's answer — *not an LPE* — **stands**. A consumer-shaped read is not an escalation, and nothing
here demonstrates one.

But §17's *reasoning* needs one correction: I wrote that "nothing frees, tears down, or
short-circuits on the value." That is no longer supportable. There **is** a site that reads the value
and branches, in the completion path, with a diagnostic that names the exact hazard. So the honest
restatement of gap 2 in §17.2 is:

> A consumer exists (§18.1). Whether it guards the operation or merely reports it is unresolved, and
> that single question is what separates "hardening defect" from "memory-safety defect".

---

## 19. RESOLVED — and it invalidates the premise of the whole finding

§18.2 left one question: does `0xb41f6bc` return? It does not.

### 19.1 The helper is `vpanic`

`0xfffffff00b41f6bc` is a thin wrapper:

```
0xfffffff00b41f6bc  pacibsp
0xfffffff00b41f6d4  mov   x6, x30
0xfffffff00b41f6d8  xpaci x6              ; strip PAC from the caller's return address
0xfffffff00b41f6f4  bl    #0xfffffff00aba5090
0xfffffff00b41f6f8  pacibsp               ; <-- an unrelated function prologue, no return emitted
```

and its callee `0xfffffff00aba5090` is a panic implementation — it takes a 0x1c0 frame, reads a global
re-entrancy guard at `__DATA+0xc48`, zeroes a 0x100-byte buffer, calls `0xfffffff00b13c74c` (a
`vsnprintf`-shaped formatter) and then loops. Decisive check:

```
retab count in 0xfffffff00aba5090 .. +0x400 :  0
ret   count in 0xfffffff00aba5090 .. +0x400 :  0
```

**Zero returns. It never comes back.** The `bl`-with-no-following-code pattern at both
`0xb41f6bc`'s tail and the assert block at `0xb343db0` is the compiler's signature for a
non-returning callee.

### 19.2 Both guards are FATAL, which kills the wrap

`0xb41f6bc` is the same helper the **`_dmaReferences overflow`** path calls. The findings note §2 read
that path as *"LOG + EARLY RETURN — but the `ldaddh` ALREADY STOOD"*, and the note's headline
concluded that the signed compare is a hole you can slip through past `0x8000`.

**That reading is wrong. Both sites panic.**

* `_dmaReferences overflow` → `bl 0xb41f6bc` → **panic**.
* `complete() while dma active` → `bl 0xb41f6bc` → **panic**.

So the counter's reachable range is **0 … 0x3FFF (16,383)**. To get to `0x8000` — where the signed
compare would sign-extend negative and "silently pass" — the increment must first traverse
`0x4000 … 0x7fff`, and the *first* step into that range takes the `cmp w8, #0x4000 / b.lt` branch to
the panic path. **The signedness hole is unreachable. It is a latent code defect, not a bypass.**

The note's sentence *"The overflow log will fire 16,384 times — noisy but log-only; past 0x8000 it
goes quiet"* is incorrect: it fires **once**, and the kernel dies.

### 19.3 What this means

| claim | before | now |
|---|---|---|
| signed compare on a 16-bit counter is a defect | yes | **yes — the code is wrong** |
| the hole is reachable past `0x8000` | claimed | **no — the `0x4000` guard panics first** |
| the counter can wrap to zero while DMA is outstanding | claimed | **no — unreachable** |
| `complete()` can run with DMA active | hypothesised UAF | **no — the consumer panics instead of proceeding** |
| severity | "counter-integrity defect, wrap reachable" | **latent defect; no reachable consequence** |

**This also explains why Apple has not changed it in 27.2b1** (§0): there is nothing to fix in
practice. The guard Apple added in GM is effective precisely because it is fatal; the signed-compare
quirk never gets a chance to matter.

**And it settles §17 definitively: there is no LPE here, and not even a reachable defect.** The
chain is real — a sandboxed process does reach the increment (§11–§15), and the increment's bound is
genuinely mis-signed (§1–§3) — but the range in which the mis-signing matters cannot be entered.

### 19.4 A runtime drive would be pointless, and I am not going to build one

The user asked for a runtime drive. **The honest answer is that it cannot achieve its goal, and
building one would only produce a kernel panic.** Driving `_dmaReferences` upward runs into the fatal
`0x4000` guard at step 16,384; there is no sequence of operations that skips it, because the counter
advances one at a time and the guard sits on the only path. The maximum a drive could demonstrate is
a **panic at ~16k outstanding references** — a DoS at best, and one that requires the driver to
tolerate 16k pins without the guard being hit earlier by normal operation.

**Recommendation:** do not build the drive. The finding's value is now the *latent-defect* note
(§1–§3 stand as a code-quality observation: a signed compare on an unsigned-in-practice 16-bit
refcount, and only 1 of 4 increment sites bounded) plus the *reachability* work (§11–§15). Both are
real; neither is an LPE.

### 19.5 The one thing that would reopen it

If `0xb41f6bc` were ever non-fatal — e.g. a build variant where the panic is downgraded to a log
(`os_variant`-gated), or an Apple change that makes it recoverable — then §3's signedness hole becomes
live again and §18's consumer becomes a genuine UAF. That is worth checking across build variants
(24A5370h, 24A437, research kernels) rather than assuming this one is representative. On **24A435 and
27.2b1 it is fatal**, and the chain stops there.

### 19.6 Verification of §19, and a near-miss worth recording

§19 was challenged (reasonably) and re-verified. It holds, and the *reason* it briefly looked wrong is
a reusable trap.

**The full body of `0xfffffff00aba5090` is `0xaba5090 … 0xaba552c` — 1180 bytes, 295 instructions,
and it contains 0 `ret` and 0 `retab`.** Its terminal sequence is:

```
0xfffffff00aba551c  bti  c
0xfffffff00aba5520  b    #0xfffffff00aba5524
0xfffffff00aba5524  wfe                     ; halt loop
0xfffffff00aba5528  b    #0xfffffff00aba5524
```

and its body is a textbook panic: zero a 0x100-byte buffer, `bl 0xfffffff00b13c74c` (a
`vsnprintf`-shaped formatter), two `bl 0xfffffff00abfb884` prints, `bl 0xfffffff00aba551c` (the halt),
and a recursive `bl 0xfffffff00b41f6bc` at `0xaba54fc`. **It is `panic()`. It never returns.**

**The two false leads, both of which I followed before rejecting them:**

1. *"There is a `retab` at `0xaba58ec`, so it returns."* — **Wrong**: `0xaba58ec` is past
   `0xaba552c`, i.e. inside the *next* function. A scan that does not bound itself to the function's
   real extent will pick up the neighbour's `ret`.
2. *"The code right after `bl 0xb41f6bc` at `0xb345568` is live, so the call must return."* —
   **Wrong**: `0xb345568` is a **branch target from `0xb345510`**, so it is live for a *different*
   path. Dead fall-through immediately after a non-returning call is completely normal; the presence
   of live code there says nothing about the call's return behaviour.

**The rule:** to decide whether a callee returns, bound the scan to the callee's own body — start at
its `pacibsp` and stop at the next function start — and look for `ret`/`retab` **inside** that range.
Do not infer it from what follows a call site.

---

## 20. §19 WAS WRONG — the wrap IS reachable, via the UNCHECKED branch

§19 concluded "the wrap is unreachable, because the `0x4000` guard panics." **That conclusion is
wrong**, and the error was looking at only one of the two increment branches.

### 20.1 The re-verified site table

Re-running the `+0x34` enumeration on 24A435 (unchanged from §2):

```
sites on +0x34: 4   bounded: 1   UNBOUNDED: 3

0xfffffff00ae5448c  ldadd  w10, w9, [x9]    sxth ABSENT   *** NO BOUND ***   (ifvlan, 32-bit, different object)
0xfffffff00b3409dc  ldaddh w9, w8, [x8]     sxth ABSENT   *** NO BOUND ***   <-- THE RETAIN HELPER
0xfffffff00b345538  ldaddh w9, w8, [x8]     sxth yes      bound 0xb345544   <-- the ONLY bounded site
0xfffffff00b345750  ldaddh w9, w8, [x8]     sxth ABSENT   *** NO BOUND ***   (the decrement)
```

The `0x4000` guard that §19 analysed lives at `0xb345544` — **inside `0xb345538`, the checked
inline op-3 path.** The RETAIN helper is a *different* function:

```
0xfffffff00b3409a4  RETAIN helper
0xfffffff00b3409d4  add    x8, x0, #0x34
0xfffffff00b3409d8  mov    w9, #1
0xfffffff00b3409dc  ldaddh w9, w8, [x8]      ; ++ _dmaReferences
0xfffffff00b3409e0  cbnz   w8, #0xfffffff00b340a14   ; old != 0 -> plain return
0xfffffff00b3409e4  ...
0xfffffff00b3409f0  str    x19, [x0, #0x38]   ; 0->1: store the owner
0xfffffff00b340a14  ... epilogue
```

**No `sxth`, no `cmp`, no panic call, no bound of any kind.** The `bl 0xfffffff00b41f6bc` at
`0xb3409a0` belongs to the *preceding* function, not this one.

### 20.2 Why that makes the wrap reachable

Per §3.4/§3.5 and §8.3, the two increment paths are exact complements on `cmd->[0x40]`:

| `cmd->[0x40]` | descriptor class | path | increment site | bound |
|---|---|---|---|---|
| `== 0` | `IOGeneralMemoryDescriptor` | descriptor **op-3** | `0xb345538` | `cmp #0x4000` → **panic** |
| `!= 0` | **`IOBufferMemoryDescriptor`** | descriptor **op-5** | **`0xb3409dc`** | **NONE** |

So on a **B-class descriptor** (`IOBufferMemoryDescriptor`) the increment goes through the RETAIN
helper, which has **no bound at all**. The counter passes `0x4000` **silently**, passes `0x8000`,
walks `0x8001 … 0xffff`, and **wraps to `0x0000`** — with no panic anywhere on that path.

### 20.3 And the consumer is then defeated — the UAF

The consumer at `0xfffffff00b343bdc` is:

```
0xfffffff00b343bdc  ldrh  w8, [x0, #0x34]        ; w8 = _dmaReferences
0xfffffff00b343be0  cbnz  w8, #0xfffffff00b343db0   ; != 0 -> panic "complete() while dma active"
0xfffffff00b343be4  ...                            ; == 0 -> PROCEED
0xfffffff00b343c04  bl    #0xfffffff00b340a44      ; the out-of-line RELEASE helper
```

The guard tests `_dmaReferences != 0`. **A counter that has wrapped to zero reads as "no DMA in
flight"**, the guard is satisfied, and `complete()` **proceeds to tear the descriptor down while DMA
references are genuinely outstanding** — exactly the premature-free-while-DMA-in-flight the findings
note originally described, and exactly what the note's §6 said it could not find a consumer for.

### 20.4 The working chain on 24A435

```
sandboxed app  /  attacker-controlled JPEG
 -> ImageIO -> XPC -> com.apple.ImageIOXPCService        [holds iokit-user-client-class =
                                                          AppleJPEGDriverUserClient;
                                                          videotoolbox.decode-in-process = true]
 -> loads JPEGH1.videodecoder in-process
 -> IOServiceMatching("AppleJPEGDriver") -> IOServiceOpen
 -> IOConnectCallStructMethod(selector 7, in 3488, out 3488)
 -> thunk 0x9022eb4 -> 0x901a348 -> IOCommandGate::runAction(queue_io_gated)
 -> queue_io_gated 0x9018c0c -> setupBuffersForCoding_gated / doRestOfBufferSetupFor*_gated
 -> AppleJPEGDart::mapMemoryDescriptor 0x901b2cc
 -> IODMACommand::setMemoryDescriptor
 -> [B-class IOBufferMemoryDescriptor]  cmd->[0x40] != 0  ->  op-5
 -> RETAIN helper 0xfffffff00b3409a4 -> ldaddh ++    *** NO BOUND ***
 -> repeat -> counter passes 0x4000 silently -> 0x8000 -> 0xffff -> wraps to 0
 -> IODMACommand::complete() consumer 0xfffffff00b343bdc reads 0
 -> guard satisfied -> proceeds with DMA still mapped -> premature teardown  == UAF
```

**This is a chain that can work on 24A435.** §19's "unreachable" was an artefact of analysing only
the checked branch.

### 20.5 What is still open — and it is one thing

**Whether the JPEG chain's descriptor is B-class.** Everything above is conditional on that:
`mapMemoryDescriptor`'s `desc` comes from its caller, and the caller's provenance is untraced. If it
is an `IOGeneralMemoryDescriptor`, the checked path is taken and the panic stops it at `0x4000`. If it
is an `IOBufferMemoryDescriptor`, the unchecked path is taken and the wrap is reachable.

**That is the single remaining question, and it is a bounded read**: follow `desc` back from
`mapMemoryDescriptor` (`0x901b2cc`) through the buffer-setup family to whatever creates it, and see
which class is instantiated. §16.1 already shows a fresh `IODMACommand` per call, so repeated calls on
one descriptor accumulate on one counter — the drive shape is a loop.

---

## 21. DESCRIPTOR PROVENANCE — traced to the wall

### 21.1 How far the trace gets

All four call sites of `mapMemoryDescriptor` have the same shape:

```
0x90172a8 / 0x901734c / 0x90178e8 / 0x901798c
        ldr  x0, [x20, #0x150]          ; self (the AppleJPEGDart)
        ldr  x1, [x19, #0x2d0]          ; <<< the IOMemoryDescriptor (or #0x2c8)
        ldr  w2, [x19, #0x46c]
        add  x3, x19, #0x308
        add  x4, sp, #...
        add  x5, sp, #...
        bl   0xfffffff00902b1cc         ; mapMemoryDescriptor
```

So the descriptor is a field of the **JpegRequest** (`x19`), at `+0x2c8` or `+0x2d0`. Scanning for
stores to those offsets finds where it is created:

```
0x9017ec8  ldr  x0, [x19, #0x2b8]       ; an argument (IOSurface-ish handle)
0x9017ecc  bl   0xfffffff00903c988      ; <<< the creator — an __auth_stub
0x9017ed0  str  x0, [x19, #0x2c8]

0x9017c8c  bl   0xfffffff00903c988      ; same creator
0x9017c90  str  x0, [x19, #0x2d0]

0x901c71c  bl   0xfffffff00903ca98      ; a different call (an allocator: w1 = 0x2b8)
0x901c720  str  x21, [x19, #0x2c8]      ; stores a parameter
```

`0xfffffff00903c988` is inside the JPEG kext's `__auth_stubs` (`0x903c538` + 0x680), i.e. **an external
kernel function**, and the stub loads its target from `__DATA_CONST.__auth_got` at
`0xfffffff00807c5a0`:

```
0x903c988  adrp  x17, #0xfffffff00807c000
0x903c98c  add   x17, x17, #0x5a0
0x903c990  ldr   x16, [x17]
0x903c994  braa  x16, x17
```

**The descriptor class is therefore decided by an imported kernel function — and that is where the
trace stops.**

### 21.2 Why it stops — three blocked routes

| route | result |
|---|---|
| read the `__auth_got` entry as a rebase | raw `0x8011000003357584` has **bit 63 set**, so it is a **bind**, not a rebase. The low bits are an ordinal, not an address. My `VA − 0x7004000` decoder (calibrated on the kext's *own* dispatch tables) does not apply to cross-image entries. |
| resolve the import by name | `ipsw kernel extract … --imports` reports **"Built kernelcache symbol map (0 defined symbols)"** — the kernelcache is stripped. `ipsw kernel symbolicate` requires a `--signatures` file, which is not available. |
| find a research kernelcache with symbols | the IPSW filesystem ships only `kernelcache.release.v59` (extracted). No research build in this IPSW. |

String search inside the kext is also empty: `IOBufferMemoryDescriptor` **0**, `IOGeneralMemoryDescriptor`
**0**, `withCapacity`/`withBytes`/`withAddressRange`/`withAddress`/`withPhysicalAddress` all **0**. The
only relevant names present are `IOSurface`, `mIOSurfaceRoot`, `IOMemoryDescriptor` (once, in the
`mapMemoryDescriptor` signature string) and `mapMemoryDescriptor`.

### 21.3 What the trace does suggest

The creator is called with an argument loaded from **`[x19, #0x2b8]`**, and the kext holds
`mIOSurfaceRoot`. That is consistent with the descriptor being **derived from an IOSurface** rather
than from a client address range. If so, the class is whatever IOSurface's memory-descriptor path
instantiates — **not** `IOGeneralMemoryDescriptor` (which is the `withAddressRange`/`withAddress`
family, i.e. descriptors wrapping client-supplied addresses), and therefore plausibly B-class.

**That is a hint, not a finding**, and I am labelling it as such.

### 21.4 The two things that would close it

1. **A kernelcache with a symbol table** — an internal/research build, or the same IPSW's
   `kernelcache.research.*` if one exists for another device. With symbols, `__auth_got[0x807c5a0]`
   resolves to a name and the class is immediate. **Cheapest and most decisive.**
2. **Runtime.** The branch taken is directly observable: `IODMACommand::setMemoryDescriptor` sends
   either `w1 = 0x03000001` (op 3, checked) or takes the op-5 path. A single breakpoint on
   `0xfffffff00b337ca0` during a JPEG decode answers it in one run. No kernel debugger needed if the
   `_dmaReferences overflow` log is used as the signal — it appears only on the checked path.

Until one of those is available, **the descriptor class is the one unverified link in an otherwise
complete chain**, and it is the difference between "the panic stops it" and "the unguarded branch
wraps the counter".

### 20.6 Note on the error pattern

That is now **five** conclusions I have had to retract this session, and every one was the same shape:
**concluding from a partial read of the artifact set.** `queue_io` vs `queue_io_gated`;
`AppleJPEGDriver` vs `AppleJPEGDriverUserClient`; "no unpin" vs "unpin one virtual hop away";
"callee returns" vs bounded-scan-says-it-doesn't; and now **"one guard" vs "one of two branches
guarded"**. The generalisable rule, and the one I should have applied here first: **when a finding
says a defect covers "one of N" paths, enumerate all N before concluding anything about reachability
from the covered path.**
