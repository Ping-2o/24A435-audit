# PRIV-24A435 — the descriptor class is PROVEN: the JPEG chain takes the UNBOUNDED increment

Continuation of `priv24A435_27_2b1_diff_verdict.md`. That document left exactly one open item
(§20.5, §21): **is the `IOMemoryDescriptor` the JPEG chain hands to `IODMACommand` a
`IOGeneralMemoryDescriptor` (bounded op-3 increment) or an `IOBufferMemoryDescriptor`
(unbounded op-5 increment)?** §21 declared the trace blocked at an `__auth_got` slot.

**It is not blocked, and the answer is `IOBufferMemoryDescriptor` — the unbounded path.**
Everything below is derived from the 24A435 kernelcache and the extracted kext binaries on disk.

---

## 0. HEADLINE

1. **§21.2's blocker was a decoder bug.** The ARM64E chained-pointer layout has **bit 63 = `auth`,
   bit 62 = `bind`**. The slot the verdict called a bind is an *auth rebase*, and it decodes to a
   real `__TEXT_EXEC` function.
2. **The descriptor comes from `IOSurface`.** The slot resolves to `0xfffffff00a35b584`, inside
   `com.apple.iokit.IOSurface`'s `__TEXT_EXEC` (`0xa34e240..0xa386240`), and is the accessor
   `ldr x0,[x0,#0x30] ; ret`. The JPEG kext calls it with an IOSurface and stores the result as the
   descriptor for `AppleJPEGDart::mapMemoryDescriptor`.
3. **`IOSurface` only ever builds `IOBufferMemoryDescriptor`s.** It calls
   `IOBufferMemoryDescriptor::inTaskWithOptions` (the failure string is in its `__cstring`) and the
   sibling factory; both allocate from the **IOBufferMemoryDescriptor metaclass**. Its binary
   contains **zero** occurrences of `IOGeneralMemoryDescriptor`.
4. **`IOBufferMemoryDescriptor` is the group-B implementation**, whose `dmaCommandOperation`
   **rejects op 3 outright** and whose **op-5 handler calls the retain helper `0xb3409a4`, whose
   `ldaddh` at `0xb3409dc` has no bound of any kind** — no `sxth`, no `cmp`, no panic.
5. **The op-3 (bounded) call is not merely skipped — it is never made.** `cmd->[0x40]` is
   `fMapper`, and `setMemoryDescriptor` issues the op-3 call **only when `fMapper == 0`**. The JPEG
   command is created `kMapped` with a mapper, so the branch Apple hardened in 27.0 GM is not on
   this path at all.
6. **The only op-5 issue site in the entire kernel** is `0xb3375f8`, inside `IODMACommand`'s
   slot-0xa0 method (`0xb33732c`), which relays op 5 to `(aux->[0xb0] ?: fMemory)` — the descriptor.
   The JPEG chain reaches that method through `cmd->vtable[0xb8]` (prepare), which it calls at
   `0x902b490`.

**Consequence:** the "1 of 4 atomic sites is bounded" observation is really **"1 of 2 descriptor
families is bounded"**. The family the JPEG chain uses is the one Apple did **not** harden.

---

## 1. THE BLOCKER IN §21.2 WAS A DECODER BUG

§21.2 read the raw `__auth_got` qword `0x8011000003357584` as "bit 63 set → bind, low bits are an
ordinal". For the ARM64E chained-pointer family (this kernelcache reports
`pointer_format = 8` = `DYLD_CHAINED_PTR_ARM64E_KERNEL`):

```
dyld_chained_ptr_arm64e_auth_rebase:
    target:32  diversity:16  addrDiv:1  key:2  next:11  bind:1  auth:1
    ^ bit 0-31 ^ 32-47       ^ 48       ^49-50 ^51-61  ^62     ^63
```

`0x8011000003357584` → `auth=1`, `bind=0` → an **auth rebase**, `target = 0x03357584`, and the
kernel's rebase bias is the low 32 bits of the image base (`0x7004000`), so
**`VA = 0xfffffff007004000 + 0x03357584 = 0xfffffff00a35b584`**. Calibration against the known-good
JPEG dispatch table (`0x8050bcad_0201eda4 → 0xfffffff009022da4`) confirms the decoder.

```
$ python3 p1_import.py
slot 0xfffffff00807c5a0  (None)
  raw qword = 0x8011000003357584
  auth=1 bind=0 next=2
  as target:32 target=0x003357584 -> 0xfffffff00a35b584  in_text=True
  --- target disassembly (0xfffffff00a35b584) ---
   0xfffffff00a35b584  bti      c
   0xfffffff00a35b588  ldr      x0, [x0, #0x30]
   0xfffffff00a35b58c  ret
```

And the stub that uses the slot is the one the verdict identified:

```
0xfffffff00903c988  adrp     x17, #0xfffffff00807c000
0xfffffff00903c98c  add      x17, x17, #0x5a0
0xfffffff00903c990  ldr      x16, [x17]
0xfffffff00903c994  braa     x16, x17
```

So the call at `0x9017ecc` — `ldr x0,[x19,#0x2b8] ; bl 0x903c988 ; str x0,[x19,#0x2c8]` — obtains the
descriptor as **`[[x19,#0x2b8] + 0x30]`**, exactly as §21.1 described. Only the *identity* of the
accessor was missing.

---

## 2. THE ACCESSOR IS AN `IOSurface` METHOD, AND ITS IMPORTERS NAME IT

`0xa35b584` lies in `com.apple.iokit.IOSurface`'s `__TEXT_EXEC`. Mapping it required a VA→kext map,
which the kernelcache does not provide directly — but the **extracted kexts do**: each is a linked
Mach-O whose `LC_SEGMENT_64` commands carry the *kernelcache runtime* VAs, so the attribution is
exact (not a layout guess).

```
$ python3 p10_map.py 0xfffffff00a35b584 0xfffffff00b3406a4 0xfffffff00b3454d0 0xfffffff00b343980
0xfffffff00a35b584 -> com.apple.iokit.IOSurface
0xfffffff00b3406a4 -> com.apple.kernel
0xfffffff00b3454d0 -> com.apple.kernel
0xfffffff00b343980 -> com.apple.kernel
```

The accessor is referenced from exactly **12** `__auth_got` slots, one per importing kext:

| # | importer | stub |
|---|---|---|
| 1 | `com.apple.driver.AppleAVD` | `0x86c20c4` |
| 2 | `com.apple.driver.AppleAVE2` | `0x8892778` |
| 3 | `com.apple.driver.AppleH16ANEInterface` | `0x8d66140` |
| 4 | `com.apple.driver.AppleH16CameraInterface` | `0x8e051cc` |
| 5 | **`com.apple.driver.AppleJPEGDriver`** | `0x903c988` |
| 6 | `com.apple.driver.AppleM2ScalerCSCDriver` | `0x9193168` |
| 7 | `com.apple.driver.ApplePearlSEPDriver` | `0x9393b34` |
| 8 | `com.apple.driver.AppleProResHW` | `0x9406a10` |
| 9 | `com.apple.iokit.IOGPUFamily` | `0xa087f40` |
| 10 | `com.apple.iokit.IOMobileGraphicsFamily-DCP` | `0xa19d750` |
| 11 | `com.apple.iokit.IOMobileGraphicsFamily` | `0xa1c09a0` |
| 12 | `com.apple.audio.TrustedClockingKEXT` | `0xa9426fc` |

**Every importer is a DMA engine that moves data out of IOSurface-backed memory.** That is the
signature of `IOSurface`'s "give me the descriptor I can DMA" accessor. Combined with the JPEG
kext's own `bool AppleJPEGDriver::isSurfaceMultiPlane(IOSurface *)` and `mIOSurfaceRoot`, the
identification of `[JpegRequest+0x2b8]` as an **IOSurface** and `[IOSurface+0x30]` as its
**IOMemoryDescriptor** is solid. *(Confidence: STRONG. One caveat is recorded in §6 — no store to
`[JpegRequest+0x2b8]` exists anywhere in the JPEG kext, so the step rests on the accessor's
identity rather than on a traced write site.)*

---

## 3. `IOSurface` BUILDS `IOBufferMemoryDescriptor`s — AND NEVER MENTIONS THE OTHER CLASS

```
$ strings-check on /Users/pauyedin/24A435__iPhone17,5/kexts/com.apple.iokit.IOSurface
  IOGeneralMemoryDescriptor   0
  IOBufferMemoryDescriptor    1     <- 'IOBufferMemoryDescriptor::inTaskWithOptions failed to
                                        allocate a surface shared block.'
```

That one string is referenced from exactly one place:

```
0xfffffff00a36fe30  adrp  x0, #0xfffffff007a11000
0xfffffff00a36fe34  add   x0, x0, #0xbe8        ; the string
0xfffffff00a36fe38  bl    #0xfffffff00a3828fc  ; log
```
…and it is the failure branch of:

```
0xfffffff00a36fcb0  ldr   x2, [x22]
0xfffffff00a36fcb8  movk  w8, #1, lsl #16
0xfffffff00a36fcc0  mov   w1, #0x4000
0xfffffff00a36fcc4  bl    #0xfffffff00a382cec   ; -> stub 0xfffffff00a382cec
0xfffffff00a36fcc8  mov   x28, x0
0xfffffff00a36fcf0  str   x28, [x19, #8]        ; the created descriptor
0xfffffff00a36fcf4  cbz   x28, #0xfffffff00a36fe30   ; -> the failure log
```

Resolving that stub names the factory:

```
$ python3 p2_stub.py 0xfffffff00a382cec 0xfffffff00a382cfc
stub 0xfffffff00a382cec -> slot 0xfffffff008328340 -> auth-rebase 0xfffffff00b3355e0
stub 0xfffffff00a382cfc -> slot 0xfffffff008328348 -> auth-rebase 0xfffffff00b33527c
```

and `0xb3355e0` is a metaclass factory:

```
0xfffffff00b335600  adrp     x0, #0xfffffff00b7a0000
0xfffffff00b335604  add      x0, x0, #0x1f8          ; the metaclass
0xfffffff00b335618  ldr      x8, [x16, #0x68]!       ; OSMetaClass::alloc
0xfffffff00b335620  blraa    x8, x16
0xfffffff00b335640  mov      x17, #0x128
0xfffffff00b335644  add      x16, x16, x17
0xfffffff00b335648  ldr      x8, [x16]               ; vtable[0x128] = the init
0xfffffff00b335650  mov      x2, x21                 ; arg
0xfffffff00b335654  mov      x3, x20
0xfffffff00b335658  mov      x4, x19
0xfffffff00b33565c  mov      x5, #0
0xfffffff00b335664  blraa    x8, x16
```

**`[0xb7a01f8]` is the `IOBufferMemoryDescriptor` metaclass.** Twelve factories in the
`0xb334710`–`0xb3358e8` cluster allocate from it — `0xb3355e0` (`inTaskWithOptions`), `0xb33527c`
(`withCapacity`), and the rest of that family. The IOSurface kext imports two of them
(`__auth_got` slots `0x8328340`, `0x8328348`).

So: **the only descriptor class IOSurface ever instantiates is `IOBufferMemoryDescriptor`.**

---

## 4. `IOBufferMemoryDescriptor` IS THE GROUP-B IMPLEMENTATION — op 3 UNSUPPORTED, op 5 UNBOUNDED

The two `dmaCommandOperation` implementations behind the nine vtables of the earlier note:

| group | vtables | `dmaCommandOperation` | op 3 (arg 1) | op 5 |
|---|---|---|---|---|
| **A** | 4 (`0x7e47f00`, `0x7e480d8`, `0x7e7f8e8`, `0x7e7faf0`) | `0xb3454d0` | **bounded** `++` (`cmp #0x4000` → `vpanic`) | big branch, **no refcount** |
| **B** | 5 (`0x7e46758`, `0x7e47888`, `0x7e47bd8`, `0x7e47da8`, `0x7e7f708`) | `0xb3406a4` | **UNSUPPORTED** (`0xe00002c2`) | **UNBOUNDED `++`** |

**Group B is `IOBufferMemoryDescriptor`**, proven by the string on its own free path:
`'Attempting to free IOBMD with page allocated flag'` lives at `0xfffffff0070c1a15` and has exactly
one `adrp+add` xref, `0xb334700` — directly adjacent to `0xb334780`, the first of the 11 installers
of vtable `0x7e47da8`.

### 4.1 Group B rejects op 3

```
0xb3406cc  mov   w8, #-0x1000000
0xb3406d0  add   w8, w1, w8
0xb3406d4  lsr   w8, w8, #0x18          ; w8 = op byte
0xb3406d8  cmp   w8, #2
0xb3406dc  b.le  #0xfffffff00b34071c
...
0xb34071c  cbz   w8, #0xfffffff00b340824   ; op 1 -> prepare-ish
0xb340720  cmp   w8, #1
0xb340724  b.ne  #0xfffffff00b34091c      ; anything else -> error
0xb34091c  sub   w0, w0, #0x25            ; 0xe00002e7 - 0x25 = 0xe00002c2
```
`op 3` (the pin the 27.0 GM fix guards) has **no handler at all** on this class. Apple's bound is
not merely bypassed here; it does not apply.

### 4.2 Group B's op 5 calls the unbounded retain helper

```
0xb3406e8  cmp   w8, #4
0xb3406ec  b.eq  #0xfffffff00b34079c        ; op 5
...
0xb34079c  cmp   w3, #0x58
0xb3407a0  b.lo  #0xfffffff00b340920        ; undersized buffer -> error
0xb3407a4  ldp   x20, x21, [x2]
0xb3407b4  ldr   w10, [x19, #0x20]
0xb3407b8  tst   w10, #0x8000
0xb3407bc  mov   w10, #3
0xb3407c0  csinc w4, w10, wzr, eq
0xb3407c4  ldr   x16, [x20]
0xb3407d4  mov   x17, #0x550
0xb3407d8  add   x16, x16, x17
0xb3407dc  ldr   x10, [x16]
0xb3407e8  mov   x0, x20
0xb3407ec  mov   x1, x19                    ; x19 = the DESCRIPTOR (self)
0xb3407f0  mov   x2, x8
0xb3407f4  mov   x6, x21
0xb340800  blraa x10, x16                   ; the mapper call
0xb340804  cbnz  w0, #0xfffffff00b340920
0xb340808  ldr   x3, [x22]
0xb34080c  mov   x0, x19                    ; x0 = the DESCRIPTOR
0xb340810  mov   x1, x20
0xb340814  mov   x2, x21
0xb340818  bl    #0xfffffff00b3409a4        ; <<< THE RETAIN HELPER
```

and the helper itself, in full:

```
0xfffffff00b3409a4  pacibsp
...
0xfffffff00b3409d0  cbz   x2, #0xfffffff00b340a14     ; x2 == 0 -> skip
0xfffffff00b3409d4  add   x8, x0, #0x34              ; &_dmaReferences
0xfffffff00b3409d8  mov   w9, #1
0xfffffff00b3409dc  ldaddh w9, w8, [x8]              ; post-increment
0xfffffff00b3409e0  cbnz  w8, #0xfffffff00b340a14    ; old != 0 -> plain return
0xfffffff00b3409e4  cbz   x19, #0xfffffff00b340a10
0xfffffff00b3409e8  ldrh  w1, [x0, #0x30]
0xfffffff00b3409ec  cbz   w1, #0xfffffff00b340a10
0xfffffff00b3409f0  str   x19, [x0, #0x38]           ; 0 -> 1: record the owner
0xfffffff00b3409f4  ldr   x2, [x0, #0x50]
0xfffffff00b3409f8  mov   x0, x19
0xfffffff00b340a0c  b     #0xfffffff00acfa148
0xfffffff00b340a14  ldp   x29, x30, [sp, #0x20]
0xfffffff00b340a20  retab
```

**No `sxth`. No `cmp`. No bound. No panic path.** Compare group A's site, which is the only one
Apple hardened:

```
0xfffffff00b345538  ldaddh  w9, w8, [x8]
0xfffffff00b34553c  cbz     w8, #0xfffffff00b345758
0xfffffff00b345540  sxth    w8, w8
0xfffffff00b345544  cmp     w8, #4, lsl #12       ; #0x4000
0xfffffff00b345548  b.lt    #0xfffffff00b34575c
0xfffffff00b34554c  ... bl  #0xfffffff00b41f6bc  ; vpanic (non-returning)
```

So `_dmaReferences` is a 16-bit counter at `descriptor+0x34` that, **on the `IOBufferMemoryDescriptor`
implementation, increments without any ceiling** — free to walk `0x4000`, `0x8000`, `0xffff` and
**wrap to 0**.

---

## 5. THE JPEG CHAIN TAKES THAT PATH — AND NEVER TOUCHES THE HARDENED ONE

### 5.1 `cmd->[0x40]` is `fMapper`, not a class discriminator

`IODMACommand::setMemoryDescriptor` (`0xb337ad8`) tail:

```
0xb337c84  ldr   x8, [x19, #0x40]        ; fMapper
0xb337c88  cmp   x8, #0
0xb337c8c  cset  w8, eq                  ; w8 = (fMapper == 0)
0xb337c90  ldr   x9, [x19, #0x70]
0xb337c94  strb  w8, [x9, #0x7e]         ; stash the flag
0xb337c98  ldr   x8, [x19, #0x70]
0xb337c9c  ldrb  w8, [x8, #0x7e]
0xb337ca0  cbz   w8, #0xfffffff00b337ccc ; fMapper != 0  -> SKIP
0xb337cb4  mov   w1, #1
0xb337cb8  movk  w1, #0x300, lsl #16     ; w1 = 0x03000001 = the PIN
0xb337cbc  mov   x2, x19
0xb337cc0  mov   w3, #0
0xb337cc8  blraa x8, x16                 ; descriptor->dmaCommandOperation(0x03000001, cmd, 0)
```

`cmd->[0x40]` is the **mapper**, confirmed by its construction in `initWithSpecification`
(`0xb335a38`) and by its use as the mapper in the segment generator (`0xb337460`). It is set for
`kMapped` commands to the lazily-initialised system mapper (`0xfffffff00b727850`, whose init routine
at `0xb33ab04` passes the string **`'waitForSystemMapper'`**).

The JPEG command is created `kMapped`:

```
0x902b2ec  ldr   x6, [x8]                ; x6 = mapper (AppleJPEGDart's registered IODARTMapper)
0x902b2f4  ldr   x16, [x16, #0x6b8]      ; x0 = IODMACommand's outSegFunc (0xb338e80)
0x902b304  mov   w1, #0x40               ; numAddressBits = 64
0x902b308  mov   x2, #0                 ; maxSegmentSize
0x902b30c  mov   w3, #0                 ; mappingOptions = kMapped
0x902b310  mov   x4, #0
0x902b314  mov   w5, #1                 ; alignment
0x902b318  mov   x7, #0
0x902b31c  bl    #0xfffffff00903c648    ; IODMACommand::withSpecification (0xb338be0)
```

⇒ `fMapper != 0` ⇒ **the op-3 call is not made**, and the bounded increment at `0xb345538` is
unreachable from this chain. (This also removes an apparent contradiction: had the op-3 call been
made on an `IOBufferMemoryDescriptor`, it would have returned `0xe00002c2` and JPEG decode would
fail outright.)

### 5.2 The prepare path reaches the only op-5 issuer in the kernel

A raw word scan of the whole `__TEXT_EXEC` finds **three** op-3/op-5/op-6 materialisations, and only
one of them is op 5:

```
0xfffffff00b337264  op6 arg0      (IODMACommand teardown/free)
0xfffffff00b3375f8  op5 arg0      <<< the only op-5 issue in the kernel
0xfffffff00b337a8c  op3 arg0      (IODMACommand unpin)
```

`0xb3375f8` is inside `IODMACommand`'s slot-0xa0 method (`0xb33732c`):

```
0xb337554  ldp   x19, x12, [x22, #0xb0]        ; the aux's +0xb0 object ...
0xb33758c  str   x19, [sp, #0x20]
0xb337590  cbz   x19, #0xfffffff00b3375c4
0xb3375c4  ldr   x1, [x8, #0x48]               ; ... or fMemory
0xb3375cc  bl    #0xfffffff00b337980
0xb3375e4  ldr   x16, [x19]
0xb3375ec  ldr   x8, [x16, #0x90]!             ; the DESCRIPTOR's dmaCommandOperation
0xb3375f0  add   x2, sp, #0x28
0xb3375f4  mov   x0, x19
0xb3375f8  mov   w1, #0x5000000                ; <<< op 5
0xb3375fc  mov   w3, #0x58
0xb337604  blraa x8, x16                       ; descriptor->dmaCommandOperation(op5, buf, 0x58)
```

The JPEG kext calls `cmd->vtable[0xb8]` at `0x902b490`, and slot `0xb8` (`0xb3366fc`) is a wrapper
into the prepare machinery:

```
0xfffffff00b3366fc  bti      c
0xfffffff00b336700  mov      x6, x3
0xfffffff00b336704  mov      x5, x2
0xfffffff00b336708  mov      x4, x1
0xfffffff00b33670c  ldr      x16, [x0, #0x50]        ; outSegFunc
0xfffffff00b336710  cbz      x16, #0xfffffff00b336728
0xfffffff00b336724  b        #0xfffffff00b33672c
0xfffffff00b33672c  adrp     x16, #0xfffffff00b336000
0xfffffff00b336730  add      x16, x16, #0x748         ; the validator callback 0xb336748
0xfffffff00b336740  mov      w1, #0x80
0xfffffff00b336744  b        #0xfffffff00b335fa4      ; the segment engine
```

and the validator's own gate table is the interesting part — it **requires a mapper**:

```
0xfffffff00b336784  ldr   w9, [x1, #0x5c]        ; request field
0xfffffff00b336788  sub   w10, w9, #1
0xfffffff00b33678c  cmp   w10, #0x3e
0xfffffff00b336790  b.hi  #0xfffffff00b3367c4    ; outside 1..0x3f -> error
0xfffffff00b336794  add   x10, x3, x2
0xfffffff00b33679c  lsr   x9, x10, x9
0xfffffff00b3367a0  cbz   x9, #0xfffffff00b3367c4 ; size does not fit -> error
0xfffffff00b3367a4  ldr   x9, [x1, #0x70]
0xfffffff00b3367a8  ldrb  w9, [x9, #0x7b]
0xfffffff00b3367ac  cbz   w9, #0xfffffff00b3367bc
0xfffffff00b3367b0  mov   w20, #0x2e1             ; flag set -> 0xe00002e1
0xfffffff00b3367bc  ldr   x9, [x1, #0x40]          ; fMapper
0xfffffff00b3367c0  cbz   x9, #0xfffffff00b3367b0  ; NO MAPPER -> ERROR
```

and further in the same cluster, the segment engine is re-entered through slot `0xa0`:

```
0xfffffff00b3368bc  ldp   x1, x2, [x20, #0x60]
0xfffffff00b3368c0  ldr   x16, [x19]
0xfffffff00b3368d0  ldr   x8, [x16, #0xa0]!        ; IODMACommand slot 0xa0
0xfffffff00b3368dc  mov   x0, x19
0xfffffff00b3368e0  mov   w3, #0
0xfffffff00b3368e4  mov   w4, #1
```

⇒ `prepare (slot 0xb8) → slot 0xa0 (0xb33732c) → descriptor->dmaCommandOperation(op 5) → impl B →
retain helper 0xb3409a4 → ldaddh @0xb3409dc, no bound.`

### 5.3 The full chain on 24A435

```
sandboxed app / attacker-controlled JPEG
 -> ImageIO -> XPC -> com.apple.ImageIOXPCService      [iokit-user-client-class =
                                                        AppleJPEGDriverUserClient;
                                                        videotoolbox.decode-in-process = true]
 -> JPEGH1.videodecoder (in-process plug-in)
 -> IOServiceMatching("AppleJPEGDriver") -> IOServiceOpen
 -> IOConnectCallStructMethod(selector 7, in 3488, out 3488)
 -> thunk 0x9022eb4 -> 0x901a348 -> IOCommandGate::runAction(queue_io_gated)
 -> queue_io_gated 0x9018c0c -> setupBuffersForCoding_gated / doRestOfBufferSetupFor*_gated
 -> AppleJPEGDart::mapMemoryDescriptor 0x902b1cc
      descriptor := IOSurface_accessor( [JpegRequest+0x2b8] ) = [IOSurface+0x30]
                    ^ 0xa35b584 in com.apple.iokit.IOSurface; IOSurface's own descriptors are
                      created by IOBufferMemoryDescriptor::inTaskWithOptions
 -> IODMACommand::withSpecification (kMapped + IODARTMapper)  -> fMapper != 0
 -> IODMACommand::setMemoryDescriptor 0xb337ad8
      op 2  (always)  -> IOBufferMemoryDescriptor op 2  -> no refcount change
      op 3  (SKIPPED: fMapper != 0)                     -> the hardened branch is never entered
 -> cmd->vtable[0xb8]  prepare 0xb3366fc -> 0xb335fa4 (validator requires fMapper != 0)
 -> cmd->vtable[0xa0]  0xb33732c -> descriptor->dmaCommandOperation(0x05000000, buf, 0x58)
 -> IOBufferMemoryDescriptor::dmaCommandOperation 0xb3406a4, op 5 -> 0xb34079c
 -> retain helper 0xb3409a4 -> ldaddh w9, w8, [descriptor+0x34]   *** NO BOUND ***
```

**Every link is now evidenced at the binary level.** §20.5's open question is answered in the
direction that makes the finding live.

---

## 6. HONEST STATUS — what this does and does not change

### Now proven (byte-exact, reproducible with the scripts in §7)

1. The §21.2 blocker was a decoder bug; the `__auth_got` slot resolves to `0xa35b584`, an accessor in
   `com.apple.iokit.IOSurface`.
2. The descriptor on the JPEG path is `[IOSurface+0x30]`, and IOSurface only ever instantiates
   `IOBufferMemoryDescriptor` (its `__cstring` has that class and **zero** mentions of
   `IOGeneralMemoryDescriptor`; both factories it imports allocate from the same metaclass).
3. `IOBufferMemoryDescriptor` = the group-B `dmaCommandOperation` (`0xb3406a4`): **op 3 unsupported**,
   **op 5 → the retain helper → an `ldaddh` with no bound**.
4. `cmd->[0x40]` is `fMapper`; the op-3 (bounded) call is issued only when `fMapper == 0`, which is
   not the case for the JPEG command.
5. The only op-5 issue site in the entire kernel is `0xb3375f8`, and the JPEG chain reaches it
   through `cmd->vtable[0xb8]` → `cmd->vtable[0xa0]`.

### Still not proven — and the one that matters

**The `0x10000` drive.** Nothing here demonstrates the counter reaching `0x10000` at runtime, and
the counter is *balanced* in normal operation: op 5 (`++`) is paired with op 6 (`--`, via the
release helper `0xb340a44`) when the command is torn down. Wrapping therefore still requires an
**unbalanced accumulation** — the leak §16.6 found (the JPEG caller drops the command on its
post-prepare failure path at `0x902b49c` while the `++` has already happened), repeated ~65,536
times against the *same* descriptor. Since the descriptor belongs to the caller's IOSurface and is
persistent, repeated decodes on one surface do accumulate on one counter. That mechanism is
**strong but not demonstrated**, and the exact trigger for the post-prepare failure is still
unconfirmed.

Also unchanged: **no memory-safety consequence has been demonstrated.** The consumer at
`0xb343bdc` (`'complete() while dma active'`) is satisfied by a wrapped-to-zero counter, which is
the UAF shape — but that remains a *shape*, not an observation.

### Corrections to the earlier verdict

| earlier claim | corrected |
|---|---|
| §21.2: the `__auth_got` slot is a bind, unresolvable | bit 63 = `auth`, not `bind`; it decodes to `0xa35b584` |
| §8.3/§20.2: `cmd->[0x40]` selects the A/B branch | `cmd->[0x40]` is `fMapper`; the op-3 call is gated on `fMapper == 0` |
| §2/§3: "1 of 4 `+0x34` sites is bounded" | better stated as **1 of 2 descriptor families is bounded** — and the JPEG chain uses the other one |
| §20.2: "on a B-class descriptor the increment goes through the RETAIN helper" | correct, and now *located*: op 5 → `0xb340818` → `0xb3409a4` → `0xb3409dc` |

---

## 7. ARTIFACTS

All under `analysis/priv24A435/priv_reach/`.

| file | purpose |
|---|---|
| `p1_import.py` | decode `__auth_got` slots with the correct ARM64E chained-pointer layout (auth vs bind) |
| `p2_stub.py` | resolve an `__auth_stub` → GOT slot → target VA |
| `p3_vt.py` | dump a vtable, decoding each slot |
| `p4_xref.py` | `bl` callers, `adrp+add` xrefs, nearest function start |
| `p5_map.py` | map the nine descriptor vtables to their `dmaCommandOperation` |
| `p6_find.py` | pointer / load-store-offset / op-code searches |
| `p7_kext.py` | prelink-plist VA→kext attempt (**superseded** — see `p10_map.py`) |
| `p8_va2kext.py` | `__TEXT_EXEC` layout guess (**superseded**) |
| `p9_kmod.py` | runtime `kmod_info` walk (**partially works**; the `address` field is not relocated) |
| **`p10_map.py`** | **authoritative** VA→kext map from the extracted kexts' `LC_SEGMENT_64` |
| `p11_iostr.py` | find a string in an extracted kext and disassemble its `adrp+add` xrefs |
| `p12_imports.py` | list every `__auth_got` import of a kext, resolved against the kernelcache |
| `p13_strs.py` | list every string a code range references |
| `kdis.py` | disassembly windows, GOT decode, `--win` |
| `strs.py` | read strings at VAs |

Gotchas that cost a round each, now encoded:

* **ARM64E chained pointers:** bit 63 = `auth`, bit 62 = `bind`. An *auth rebase* is still a
  rebase. Reading bit 63 as "bind" makes the whole `__auth_got` look unresolvable.
* **The kernelcache has almost no section headers** (`nsects = 0` for `__DATA_CONST`,
  `__TEXT_EXEC`, …). Section-based scans silently find nothing — scan *segments*.
* **The extracted kexts are the VA authority.** Each is a linked Mach-O whose segment VAs are the
  kernelcache runtime addresses; the prelink plist's `_PrelinkExecutableLoadAddr` is the *original*
  layout and the kmod `address` field is not relocated.
* **`imm9` in a pre/post-indexed `ldr` is a signed BYTE offset, not scaled.** Multiplying by 8
  shifts every hit by 8x and hides the sites you are looking for.
* **`fn_start` by "nearest preceding `retab`" fails on non-returning functions** (a panic tail has
  no `retab`), which merges a function with its neighbour. Bound the scan to the body.

---

## 8. UAF / LPE — the direct answer

Asked plainly: **is there a UAF or an LPE by controlling `_dmaReferences`?**

**LPE: no.** Nothing in this chain crosses a privilege boundary. The acting process is
`ImageIOXPCService` (a `platform-application` system service), so the best case is a sandbox-escape
*primitive* — and no escalation step of any kind is demonstrated.

**UAF: not demonstrated — and the sweep below is why it is hard, which is the useful part.**

### 8.1 `_dmaReferences` is a *counter*, not an *ownership guard*

Every non-`sp` reader of `descriptor+0x34` in the `IOMemoryDescriptor`/`IODMACommand` cluster
(`com.apple.kernel`, `0xb330000`–`0xb350000`) — **13 sites** — falls into exactly three classes:

| class | sites | shape | branches on the value? |
|---|---|---|---|
| **report-only** | `0xb3347d4`, `0xb335020`, `0xb33807c`, `0xb338884`, `0xb340094`, `0xb347bfc`, `0xb349214` (+ more) | `ldrh w22,[x20,#0x34] ; mov x1,w22 ; bl 0xb438dc0` | **no** |
| **decrement underflow gates** | `0xb340a6c` (release helper), `0xb345740` (impl-A unpin) | `ldrh w8,[x19,#0x34] ; cbz w8, -> vpanic` | yes → panic |
| **the one assert** | `0xb343bdc` | `ldrh w8,[x0,#0x34] ; cbnz w8, -> vpanic` | yes → panic |

The reporting helper `0xb438dc0` is a **logger, not a panic** — it contains 4 `retab`s in its first
0x400 bytes, so it returns. And the site that reads the field *inside
`IOBufferMemoryDescriptor`'s own free path* is one of the report-only ones:

```
0xfffffff00b33471c  <-- IOBufferMemoryDescriptor free
0xfffffff00b3347c4  adrp  x8, #0xfffffff007e46000
0xfffffff00b3347c8  ldr   x8, [x8, #0x448]      ; a site/telemetry table
0xfffffff00b3347cc  cbz   x8, #0xfffffff00b334808   ; not registered -> skip
0xfffffff00b3347d0  ldp   x20, x21, [x8]
0xfffffff00b3347d4  ldrh  w22, [x20, #0x34]     ; the count
0xfffffff00b3347dc  mov   x1, x22
0xfffffff00b3347e0  bl    #0xfffffff00b438dc0  ; report it, then continue freeing
```

**So nothing frees, unmaps or short-circuits on the field.** That removes the cheap UAF shapes:

* an **inflated** count does not block a free (there is no "refuse to free while DMA active"), so
  there is no leak-by-refusal and no "count as liveness check" to race;
* there is no ownership decision anywhere that reads it.

### 8.2 The three guards are all `vpanic`, and that changes the failure mode

| # | site | test | outcome |
|---|---|---|---|
| 1 | `0xb345538` (impl-A op-3/arg 1) | `sxth` + `cmp #0x4000` on the **old** value | `vpanic` `'_dmaReferences overflow'` — **group A only** |
| 2 | `0xb340a6c`, `0xb345740` | `cbz` on the current value | `vpanic` `'_dmaReferences underflow'` (line 5088) |
| 3 | `0xb343bdc` | `cbnz` on the current value | `vpanic` `'complete() while dma active'` (line 5331) |
| — | `0xb3409dc` (impl-B retain) | **none** | `ldaddh` runs unconditionally |

Two consequences:

* **The protocol panics rather than tolerating imbalance.** One net increment is therefore not a
  silent corruption — it is a **kernel panic** at the next anomaly check. So the realistic
  reachable consequence of an imbalance is **DoS by panic**, not a UAF. (Still not demonstrated
  end-to-end: it needs a leaked increment *and* a subsequent `complete()` on the same descriptor.)
* **The increment and the decrement are deliberately asymmetric**: the increment is an
  unconditional post-increment (the guard, where it exists, runs *after* the `ldaddh`), while the
  decrement is pre-checked and refuses to go below 0. Any imbalance therefore **accumulates
  permanently** — the counter is monotone in the presence of imbalance. That is what makes a wrap
  conceivable at all, and it is also what makes a stuck count a panic rather than a corruption.

### 8.3 What the UAF would actually require

To make the count read **0** while a DMA map is genuinely outstanding — i.e. to satisfy guard 3
instead of tripping it — the 16-bit counter must **wrap**, which needs

> **65,536 net unbalanced increments on one persistent descriptor.**

Constraints on that, all verified:

* the increments must be *net* — op 5 (`++`) is paired with op 6 (`--`) through the release helper
  `0xb340a44`, so a balanced decode returns the count to 0;
* the only imbalance found is the §16.6 command leak, worth **+1 per failed call**;
* the increment is itself gated — the retain helper does `cbz x2, -> return` before the `ldaddh`,
  where `x2` is the second qword of the op-5 data buffer;
* the descriptor must be the *same* object 65,536 times, i.e. one long-lived IOSurface.

No path achieving that is identified, and none is demonstrated. **Verdict: the UAF is a shape, not
a finding** — and the shape is narrower than the earlier note implied, because the field carries no
ownership semantics to subvert.

### 8.4 The honest one-line answers

| question | answer |
|---|---|
| LPE by controlling `_dmaReferences`? | **No.** No privilege boundary is crossed; no escalation primitive exists. |
| UAF? | **Not demonstrated.** Would need a full 16-bit wrap (65,536 net increments on one descriptor) to defeat a single assert. No such path identified. |
| DoS? | **The most plausible edge, also not demonstrated.** One unbalanced increment turns into a `vpanic` at the next `complete()`. |
| What is definitely real? | A mis-designed refcount: one descriptor family has **no ceiling at all**, the other was given one in 27.0 GM, the two ends are asymmetric, and the field is logged on free but never used to gate anything. A hardening defect, confirmed unfixed in 27.2b1. |

---

## 9. ATTEMPT TO PROVE THE UAF — the method, the refuted hypothesis, and the exact bar

An explicit attempt was made to prove a full UAF. **It failed, and the failure is informative:
the single most promising hypothesis was refuted by the binary.**

### 9.1 The hypothesis

If the descriptor's op-5 call (the unbounded `++`) were issued **once per segment batch** rather
than once per command, then a single decode of a fragmented IOSurface would add *thousands* to
`_dmaReferences` while `complete()` subtracts one — a ~1000:1 imbalance, and the 16-bit wrap
would fall out of one ordinary decode. That would have been a full UAF.

The segment generator `IODMACommand` slot-0xa0 (`0xb33732c`) does contain a tight per-segment loop:

```
0xb3376ac  ldr   x8, [x22, #0x60]
0xb3376b0  add   x8, x8, x21
0xb3376b4  str   x8, [sp, #0x80]
0xb3376c0  ldr   x8, [x16, #0x90]!        ; the DESCRIPTOR's dmaCommandOperation
0xb3376cc  mov   w1, #0x1000000           ; <<< op 1 — NOT op 5
0xb3376d0  mov   w3, #0x40
0xb3376d8  blraa x8, x16
0xb3376dc  cbnz  w0, #0xfffffff00b337944
0xb3376e4  add   w26, w26, #1             ; segment counter
0xb3376e8  add   x21, x8, x21
0xb3376ec  cmp   x21, x25
0xb3376f0  b.lo  #0xfffffff00b3376ac      ; <<< the per-segment loop
```

### 9.2 The refutation

**The loop issues op 1, not op 5.** Op 1 on `IOBufferMemoryDescriptor` goes to `0xb340824` and
touches no refcount. A proper intra-function CFG cycle test (`cycle.py`) confirms it directly:

```
target 0xfffffff00b3376cc   -> INSIDE A LOOP            (op 1, per segment)
target 0xfffffff00b3375f8   -> straight-line (once per call)   (op 5, the ++)
target 0xfffffff00b337264   -> straight-line (once per call)   (op 6, the --)
target 0xfffffff00b3368d0   -> straight-line (once per call)   (the generator call)
target 0xfffffff00b340818   -> straight-line (once per call)   (the retain-helper call)
```

And the two ends are 1:1 across functions: the prepare entry (`0xb3367f8`) issues op 5 once (via
`0xb3368d0`), and the complete entry (`0xb337088`) issues op 6 once. **The counter is balanced per
prepare/complete pair.**

*(Method note: the first CFG run said "straight-line" for everything, including a site that is
demonstrably inside the loop. The cause was treating `blraa` as a terminator — bit 21 of the PAC
branch family is the **link** bit, so `blraa` returns. A CFG that dead-ends at every virtual call
will confidently report "not in a loop" for most real loops. Always validate a negative result
against a site known to be in a loop.)*

### 9.3 What the wrap therefore requires — precisely

`_dmaReferences` is balanced per prepare/complete pair, so the wrap needs an **imbalance**, and the
only imbalance available is a **leaked command** (the §16.6 path: the `++` has already happened
inside prepare, then the JPEG caller drops the command at `0x902b49c` without releasing it, so the
matching `--` never runs).

One more constraint falls out of the assert's polarity, and it is the sharpest statement of the
bar:

* A **pure-leak wrap is benign.** If 65,536 commands are leaked, the count wraps to 0 while *no*
  DMA is actually outstanding — so the assert passes with nothing to tear down.
* To get a UAF, the count must read **0 at the moment a genuine DMA map is outstanding**:
  **65,535 leaks, then one genuine prepare** (count → `0x10000` → 0), **then that command's
  `complete()`** — which now passes the assert and proceeds while the map is live.

So the requirement is **65,535 deterministic leak-inducing prepares against one persistent
IOSurface descriptor, followed by one normal prepare and its completion** — plus the collateral of
65,535 leaked `IODMACommand` objects and their segment arrays. No path producing that is
identified, and nothing was demonstrated at runtime.

### 9.4 Verdict on the attempt

| claim | status |
|---|---|
| the unbounded `++` is on the JPEG chain's path | **PROVEN** (§1–§5) |
| op 5 is issued once per *segment* (large per-decode imbalance) | **REFUTED** (§9.1–9.2) |
| the increment/decrement are balanced per command | **PROVEN** |
| a leak yields +1 permanently | **PROVEN** (increment is an unconditional post-increment; the decrement is pre-checked) |
| 65,535 leaks on one descriptor is achievable | **NOT FOUND** |
| the wrap-to-0-with-live-DMA state is reachable | **NOT DEMONSTRATED** |
| **full UAF** | **NOT PROVEN** |
| **LPE** | **NOT PROVEN — and no privilege boundary is crossed anywhere in the chain** |

**Conclusion of the attempt:** this is a genuine hardening defect with a *quantified, very high*
bar to memory unsafety. It is not a reportable UAF and it is not an LPE. The honest deliverable is
the defect plus the exact requirement, not a claim of exploitation.

---

## 10. A CONCRETE DOUBLE-RELEASE LEAD IN THE JPEG DMA TEARDOWN

The `_dmaReferences` route is walled behind 65,535 leaks (§9). So the search moved to the *other*
end of the same call: the driver's own DMA bookkeeping. This produced a much cheaper candidate —
**a double release of an `IODMACommand`, requiring one failed (or skipped) map, not 65,535
anything.** It is a **lead with a named precondition, not a proven UAF.**

### 10.1 Two (descriptor, command) slots, and the map writes its slot only on success

The `JpegRequest` holds two independent DMA mappings:

| descriptor | command slot | used by |
|---|---|---|
| `+0x2c8` | `+0x300` | one `mapMemoryDescriptor` call site pair |
| `+0x2d0` | `+0x308` | the other |

`AppleJPEGDart::mapMemoryDescriptor` (`0x902b1cc`) takes the command slot **by address**
(`add x3, x19, #0x308`) and — as §16.2 established and this pass re-confirms — writes it **only on
the success path**:

```
0x902b4c8  b     #0xfffffff00902b4d8     ; every error path jumps to the common exit
0x902b4cc  ldr   x8, [sp, #0x10]
0x902b4d0  str   x8, [x20]                ; *outDva      <- success path only
0x902b4d4  str   x25, [x19]               ; *outCmd      <- success path only
0x902b4d8  ... retab
```

So **a failed map leaves the command slot holding whatever it held before.**

### 10.2 The teardown releases the command but clears only the descriptor

`0x9017fe8` is the DMA teardown (0 direct callers — it is reached indirectly). It runs the two
unmaps, and each is guarded by **nothing but a NULL check on the command slot**:

```
0x901800c  ldr   x1, [x1, #0x2c8]        ; descriptor A
0x9018010  cbz   x1, #0xfffffff009018084 ; no descriptor -> skip
0x9018014  ldr   x3, [x19, #0x300]       ; command A
0x9018018  cbz   x3, #0xfffffff009018030 ; no command    -> skip
0x9018028  bl    #0xfffffff00902b518     ; AppleJPEGDart::unmapMemoryDescriptor(desc, n, cmd, 0)
...
0x9018080  str   xzr, [x19, #0x2c8]      ; <<< clears the DESCRIPTOR
...
0x901810c  ldr   x1, [x19, #0x2d0]       ; descriptor B
0x9018114  ldr   x3, [x19, #0x308]       ; command B
0x9018118  cbz   x3, #0xfffffff00901812c
0x9018128  bl    #0xfffffff00902b518     ; unmapMemoryDescriptor(desc, n, cmd, 0)
```

**The descriptor slot is zeroed; the command slot is not.** After a teardown the request is
therefore left in the state *descriptor = 0, command = released-but-still-recorded*.

### 10.3 The per-request setup does a partial reset

`setupBuffersForCoding_gated` (reached per request — §12.2) begins:

```
0x9017ba4  add   x24, x1, #0x2b8
0x9017bac  str   q0, [x24]                ; clears +0x2b8 (IOSurface) and +0x2c0
0x9017bb0  str   wzr, [x1, #0x2d8]
0x9017bb4  strh  wzr, [x1, #0x2dc]
```

It clears the IOSurface pointer and the flags — but **not** `+0x2c8`, `+0x2d0`, `+0x300` or
`+0x308`. A *full* request reset does exist and does clear them:

```
0x90183f4  str   xzr, [x19, #0x2b8]
0x90183f8  str   q0,  [x19, #0x2c0]       ; descriptor A
0x90183fc  str   xzr, [x19, #0x2d0]       ; descriptor B
0x9018400  str   wzr, [x19, #0x2d8]
0x901840c  str   q0,  [x19, #0x300]       ; <<< BOTH command slots
0x9018410  str   wzr, [x19, #0x310]
```

…but it is a **different function** from the per-request setup, so "the slots get cleared before
every request" is not established.

### 10.4 The precondition, and why it is cheap

> **descriptor slot non-zero AND command slot holding an already-released command.**

Given §10.1–10.3 that is exactly: *a previous release left the command slot stale, and the next
`mapMemoryDescriptor` for that slot did not overwrite it* — i.e. the map **failed** or was
**skipped**. The teardown then calls `unmapMemoryDescriptor(desc, n, staleCmd, 0)` on a command
that has already been released.

Compare the two candidates:

| | `_dmaReferences` wrap (§9) | this double release (§10) |
|---|---|---|
| operations needed | 65,535 leak-inducing prepares on one object | **one** failed or skipped map |
| attacker control | none identified | the driver's own strings show it expects failures — including `'too many dart exceptions from malicious file in 1sec'` and `'ERROR, dart fail to gen segments with error code 0x%x'` |

### 10.5 What is NOT proven — three remaining links, and one that IS now resolved

**RESOLVED (was the cheapest and most important): does `unmapMemoryDescriptor` on a released command
actually dereference it, or merely decrement a refcount?** It dereferences it. The very first thing
it does with the command pointer is load its vtable and make a virtual call through it:

```
0x902b53c  mov   x19, x3                 ; x19 = the IODMACommand
0x902b540  cbz   x3, #0xfffffff00902b628 ; NULL -> bail
0x902b548  ldr   x16, [x19]              ; <<< VTABLE LOAD from the command
0x902b554  autda x16, x17
0x902b558  ldr   x8, [x16, #0x90]!       ; cmd->vtable[0x90]
0x902b564  movk  x16, #0x9c32, lsl #48   ; diversity 0x9c32 = IODMACommand slot 0x90
0x902b568  blraa x8, x16                 ; <<< INDIRECT CALL THROUGH THE COMMAND
```

So the double release is a genuine **use-after-free-shaped operation**: a vtable load plus an
indirect call through a freed `IODMACommand`. (Slot `0x90` is the command's teardown/unpin
`0xb337a00`.) The practical outcome depends on reuse: `autda` with the fixed diversity `0xcda1`
means a recycled allocation usually faults the pointer-authentication rather than yielding control
flow — so the common manifestation would be a **panic**, with a clean UAF only under favourable
reuse. Either way it is use of freed memory, not a benign refcount decrement.

**Still open — these decide whether the lead is real:**

1. **Is the `JpegRequest` reused** with a stale command slot? Needs the request alloc/pool
   lifecycle (the 0x880-byte allocation at `0x9024418` via the type-tagged allocator `0xb338e9c` is
   a candidate but unconfirmed). If a fresh zeroed request is used per job, this is dead.
2. **Can a descriptor be set while the map is skipped or fails?** `setupBuffersForCoding_gated`
   sets `+0x2c8` from the IOSurface accessor at `0x9017ed0`, and the map calls live in
   `doRestOfBufferSetupFor{Decode,Encode}_gated`. A failure *between* those two leaves the
   descriptor set with the command stale. `RequestHandling::decodeRequestValidation` /
   `encodeRequestValidation` are the obvious place to look.
3. **Is it reachable from the userclient** with attacker-controlled input? Not established.

Status: **a concrete double-free/UAF-shaped defect in the driver's DMA bookkeeping, with the
consequence confirmed and the reachability preconditions named but unproven.** It is not a
demonstrated UAF.

### 10.6 Correction to §5.2

The prepare validator's mapper gate is **narrower than §5.2 stated**. It only applies when
`cmd->[0x5c]` (numAddressBits) is in `1..0x3f`; the field is tested first and anything outside that
range short-circuits to success:

```
0xb336784  ldr   w9, [x1, #0x5c]        ; numAddressBits
0xb336788  sub   w10, w9, #1
0xb33678c  cmp   w10, #0x3e
0xb336790  b.hi  #0xfffffff00b3367c4    ; out of range -> w20 = 0 = OK
...
0xb3367bc  ldr   x9, [x1, #0x40]        ; the fMapper gate, reached only for 1..0x3f
0xb3367c0  cbz   x9, #0xfffffff00b3367b0
```

The JPEG command is created with `numAddressBits = 0x40`, so it takes the short-circuit and the
fMapper gate is never evaluated on this path. §5.2's *conclusion* is unaffected (the fMapper-gated
op-3 pin in `setMemoryDescriptor` is a separate check and still applies), but the statement that
the prepare validator "requires a mapper" is wrong for this caller.

### 10.7 LPE — unchanged

Still no privilege boundary crossed anywhere. The acting process is `ImageIOXPCService`; even a
perfect double-free there is a sandbox-escape *primitive*, and no escalation step is demonstrated.

---

## 11. THE §10 LEAD IS REFUTED — the command slots are cleared twice per request

§10 proposed a double release of an `IODMACommand` via a stale command slot. Chasing the
precondition through the request lifecycle **kills it**, and the evidence is unambiguous.

### 11.1 The abort path §10 relied on does exist — and is harmless

`setupBuffersForCoding_gated` (`0x9017b7c` … `0x9017fe8`) sets descriptor A from the IOSurface
accessor, then runs a descriptor prepare whose failure bails out **before** the command-slot clear:

```
0x9017ed0  str   x0, [x19, #0x2c8]      ; descriptor A = getter(...)
0x9017ed4  cbz   x0, #0xfffffff009017f48
0x9017ef0  blraa x8, x16                ; retain it
0x9017ef4  ldr   x0, [x19, #0x2c8]
0x9017f14  blraa x8, x16                ; descriptor->vtable[0xd8](0)   -- a prepare
0x9017f18  cbz   w0, #0xfffffff009017f70 ; success -> 0x9017f70 (clear + maps)
0x9017f1c  ... log ...                  ; FAILURE:
0x9017f44  b     #0xfffffff009017c34    ;   bail out -- 0x9017f7c is SKIPPED
...
0x9017f70  mov   w8, #1
0x9017f74  strb  w8, [x19, #0x2dc]
0x9017f7c  str   q0, [x19, #0x300]      ; clear BOTH command slots
0x9017f90  bl    #0xfffffff009017844    ; doRestOfBufferSetupForEncode_gated (maps)
0x9017fac  bl    #0xfffffff0090171fc    ; doRestOfBufferSetupForDecode_gated (maps)
```

So §10's precondition — *descriptor set, command slot stale, map never ran* — is reachable at
`0x9017f18`. The question was whether the slot can be **non-zero** at that moment.

### 11.2 It cannot: the slots are zeroed at request start and again before every map

Two independent clears stand in the way, and they are on the same `JpegRequest` object:

1. **The full request reset** — `0x90183b0`, called from the selector-7 implementation at
   `0x901a3f0`. It takes the request in `x0` (`mov x19, x0`), and the caller passes `x21`, which is
   the `JpegRequest` itself (the very next instructions store `[x21,#0x10]`, `[x21,#0x20]`,
   `[x21,#0x2ac]`). It clears `+0x300`…`+0x30F` at `0x901840c`.
2. **The pre-map clear** in `setupBuffersForCoding_gated` at `0x9017f7c`, which runs on the success
   path *before* both setup functions that perform the maps.

So at the moment the abort path at `0x9017f18` is taken, the command slots are **0** — they were
zeroed by the reset (1) and would have been zeroed again by (2) had the flow reached it. The
teardown's `cbz x3` therefore skips, and no stale command is ever unmapped.

**Verdict: §10 is a refuted lead, not a finding.** The driver's DMA bookkeeping is more careful
than it first looked: it clears the command slots redundantly (at request reset *and* immediately
before the maps), which is exactly the defence against the stale-slot double release.

### 11.3 What the refutation does *not* cover

One path remains untested and is the honest place to pick this up again: **a second
`setupBuffersForCoding_gated` pass on the same request without an intervening reset.** The
sel-7 path resets first, so a single call is safe; a retry loop that re-enters the setup on the
same object would leave the slots holding the previous pass's command while the descriptor is
re-set — which is precisely the stale-slot state. Nothing in the traced flow does that, but the
`IOCommandGate` dispatch (six selectors funnel into `queue_io_gated`) means the call count per
request is not something I have closed out.

---

## 12. THE FINISH PATH OVER-RELEASES THE CLIENT'S IOSURFACE IF ENTERED TWICE

§11 killed the *command-slot* double unmap, because the teardown clears the descriptor slots. The
same sweep found the one field where that protection is **absent** — and it is the field the client
supplies.

### 12.1 The teardown releases `JpegRequest+0x2b8` and never clears it

```
0x9018084  ldr   x0, [x19, #0x2b8]        ; <<< the IOSurface
0x9018088  cbz   x0, #0xfffffff0090180cc  ; guarded by NULL only
0x901808c  ldrb  w8, [x19, #0x2d8]
0x9018090  tbz   w8, #0, #0xfffffff0090180b0
0x9018094  ldrb  w8, [x19, #0x2da]
0x9018098  tbz   w8, #0, #0xfffffff0090180a4
0x901809c  bl    #0xfffffff00903c8c8
0x90180a0  ldr   x0, [x19, #0x2b8]
0x90180a4  mov   w1, #1
0x90180a8  bl    #0xfffffff00903c898
0x90180ac  ldr   x0, [x19, #0x2b8]
0x90180b0  ldr   x16, [x0]
0x90180c0  ldr   x8, [x16, #0x28]!        ; vtable[0x28] = OSObject::release (div 0x3a87)
0x90180c8  blraa x8, x16                  ; <<< RELEASE -- and nothing clears the slot after it
```

The access sweep over the whole JPEG kext confirms it: `[+0x2b8]` is **read** by the teardown and
**zeroed** only by the request resets (`str xzr,[x19,#0x2b8]` at `0x90183f4`, and `str q0,[x24]`
with `x24 = req+0x2b8` at `0x9017bac`). **The teardown itself never clears it.**

Contrast the same function's handling of the command slots: it *does* clear the descriptors
(`str xzr,[x19,#0x2c8]` at `0x9018080`, `str xzr,[x19,#0x2d0]` at `0x90181a4`), which is precisely
what makes the command double-unmap harmless (§11). **The IOSurface has no equivalent guard.**

### 12.2 Two entry points into the same teardown, with independent guards

The teardown (`0x9017fe8`) has exactly one caller, the helper `0x901b440`, and that helper calls it
**unconditionally**:

```
0x901b474  mov   x0, x20
0x901b478  mov   x1, x19
0x901b47c  mov   w2, #0
0x901b480  bl    #0xfffffff009017fe4      ; the DMA teardown -- no guard
```

…and `0x901b440` itself has **two** callers:

| site | enclosing function | guard | call |
|---|---|---|---|
| `0x9016f80` | `AppleJPEGDriver::finish_io_gated` (`0x9016af0`) | `ldr x8,[x19,#0x10] ; cbz x8, …` — `[req+0x10] != 0` | — |
| `0x90191bc` | `queue_io_gated` (`0x9018c0c`) | result code `w21 == 0 \|\| w21 == 0xe00002e8`, then `x23 == 0 \|\| w22 == 0` | — |

### 12.2b `finish_io_gated` itself is reached from BOTH the sync and the async path

`finish_io_gated` (entry `0x9016aec`) has exactly **two** direct callers, and they are the classic
double-completion pair:

```
; caller 1 -- AppleJPEGDriver::begin_io_gated(bool)   [0x9015c3c]
0x9015e48  ldr   x1, [x24, #8]        ; the request
0x9015e50  mov   x2, x25              ; IOReturn
0x9015e54  mov   x3, x20
0x9015e58  mov   w4, #0               ; bool = FALSE
0x9015e5c  bl    #0xfffffff009016aec  ; finish_io_gated(req, err, arg, false)   -- SYNCHRONOUS

; caller 2 -- AppleJPEGDriver::interruptOccurred_gated(JpegRequest *, uint32_t)  [0x90166d4]
0x9016730  mov   w8, #1
0x9016734  strb  w8, [x0, #0xc8]      ; a DRIVER flag (not the request)
0x9016740  mov   w4, #1               ; bool = TRUE
0x9016744  bl    #0xfffffff009016aec  ; finish_io_gated(req, 0, arg, true)    -- ASYNCHRONOUS
0x9016748  strb  wzr, [x19, #0xc8]
```

So one `JpegRequest` can be finished by **the synchronous submission path** (a failed
`begin_io_gated`, `bool = false`) and by **the hardware interrupt completion**
(`interruptOccurred_gated`, `bool = true`). Those are exactly the two entries that a driver has to
make mutually exclusive — and the one-shot guard they would use for that (`[req+0x10]`) is a field
that **neither** path clears (§12.3).

### 12.3 The guard is not consumed

A narrow store sweep over both `finish_io_gated` and the helper `0x901b440` finds **no write at all**
to `[req+0x10]`, `[req+0x2b8]`, `[req+0x2c8]`, `[req+0x2d0]`, `[req+0x300]` or `[req+0x308]`:

```
--- helper 0x901b440 (calls the teardown) [0x901b440,0x901b660) ---
--- finish_io_gated                        [0x9016c00,0x90171fc) ---
   (nothing)
```

So `finish_io_gated` **does not consume its own guard**, and the release of `[+0x2b8]` has **no
one-shot protection anywhere on the release path**. The only clear is at the *start of the next
request*.

### 12.4 The lead, stated precisely

> **If the finish path runs twice for one `JpegRequest`, the client-supplied IOSurface is released
> twice** — a plain `OSObject::release` over-release on an object the caller chose. That is the
> classic over-release UAF, and unlike §10 it is not defended by a clear.

Why this is a better lead than §10:

* the object is the **client-supplied IOSurface** (attacker-influenced), not a driver-internal
  command;
* the protection that killed §10 — clearing the slot — is **absent** here;
* the trigger is a **second finish**, not a failed map: `finish_io_gated`'s guard is a persistent
  field that nothing on the finish path clears, so the natural "already finished" defence is
  missing.

### 12.5 The one remaining question

**Can `finish_io_gated` be entered twice for one request?** That is now the whole question, and it
is a bounded read:

* identify what **sets** `[req+0x10]` (three candidates write a 32-bit value there:
  `0x9019df0`, `0x901a300`, `0x901ae20`, all `str w8,[x20,#0x10]` inside selector
  implementations) and whether it is cleared anywhere between two finishes;
* check whether the `queue_io_gated` finish (guard: result code) and the `finish_io_gated` finish
  (guard: `[+0x10]`) can both be taken for one job — the asynchronous interrupt completion and the
  synchronous error path are exactly the pair that would do it.

**Status: a lead, not a proven UAF.** The double-release primitive is confirmed
(`OSObject::release` with no slot clear and no consumed guard); the reachability of a double finish
is not.

---

## 13. LPE HUNT — the client-pointer avenue is REFUTED; the driver resolves IDs

An LPE here means a **sandboxed app gaining kernel privilege**. That reduces to: is there a kernel
primitive reachable from the JPEG userclient with client-controlled data? The classic shape is a
client-supplied value used as a **kernel pointer** — so that is what this round checked, on the one
field the teardown *releases*.

### 13.1 `JpegRequest+0x2b8` is resolved from a 32-bit ID, not supplied

A coverage-aware store sweep (any store whose address range covers `+0x2b8`, including `stp`/`str q`)
finds exactly **two** writers in the whole kext:

```
0xfffffff009017e1c  str   x0,   [x19, #0x2b8]   ; the SET
0xfffffff0090183f4  str   xzr,  [x19, #0x2b8]   ; the reset clear
```

and the set site is a **lookup**, not a copy from the client struct:

```
0x9017e0c  ldr   x0, [x20, #0x148]      ; the driver's IOSurface provider (mIOSurfaceRoot)
0x9017e10  ldr   w1, [x19, #0x2ac]      ; <<< a 32-bit ID taken from the request
0x9017e14  mov   x2, x22                ; a third argument (task-scoped lookup)
0x9017e18  bl    #0xfffffff00903c6e8    ; -> 0xfffffff00a36cbb0, inside com.apple.iokit.IOSurface
0x9017e1c  str   x0, [x19, #0x2b8]      ; store the RESOLVED object
0x9017e20  cbz   x0, #0xfffffff009017e3c
0x9017e24  mov   w22, #1
0x9017e2c  bl    #0xfffffff00903c888    ; -> 0xfffffff00a35ea68, also in IOSurface -- a RETAIN
```

`0x903c6e8` resolves (via `__auth_got`) to `0xfffffff00a36cbb0`, which lies in
`com.apple.iokit.IOSurface`'s `__TEXT_EXEC` (`0xa34e240..0xa386240`) — i.e. an
`IOSurfaceRoot`-side lookup taking the provider, a **32-bit surface ID** and a task. The driver then
**retains** the result before storing it, and the teardown releases it once.

**⇒ No client-supplied pointer reaches a kernel dereference or a release on this path.** The client
supplies an ID; the kernel resolves it, scoped to the caller's task, and refcounts it properly. The
"controlled free of an attacker-chosen pointer" LPE is **refuted**.

### 13.2 The other LPE avenues, and their status

| avenue | status | evidence |
|---|---|---|
| client-supplied kernel pointer → controlled release | **REFUTED** | §13.1 — ID-based, task-scoped lookup + retain/release |
| unvalidated `structureInputSize` on the external-method dispatch | **not present** | IOKit's `IOExternalMethodDispatch` enforces it; sel 7's record carries `structIn = structOut = 3488` and the real client sends 3488/3488 (§12.1) |
| unvalidated array index | **not present** | `-fbounds-safety` checks on every index: `nseg` is bounded to {0,1} by `cmp w28, w8 ; b.hi -> error` at `0x902b260`; the codec-slot index is bounded in `finish_io_gated` |
| client-supplied DMA address/length | **not present** | the descriptor is the IOSurface's own `IOBufferMemoryDescriptor` (§3); the segment walk is bounded by that descriptor |
| opening the userclient from an app | **not available** | no kext declares `IOUserClientEntitlements`; AppleJPEGDriver hardcodes no entitlement; the only grants found are ImageIOXPCService's entitlement and the `AccessibilityOnboarding` / Accessory / Apple-Internal profiles — all system contexts, none an app container |

### 13.3 The structural reason there is no LPE here

The chain's **acting** process is `ImageIOXPCService` — a `platform-application` system service.
An app asking ImageIO to decode an image is the *designed* interface, not an escalation; the
service is already more privileged than the app. So an LPE requires a **kernel** memory-safety bug
reachable from that service — and that is exactly what §9–§12 searched for, three times, with
clean negatives each time.

**Verdict: no LPE is demonstrated, and no LPE primitive is present.** The driver's hardening is
unusually thorough: ID-based (not pointer-based) object resolution, refcount panics on both
underflow and overflow, redundant clears on the DMA state, `-fbounds-safety` on every index, and
IOKit's own size validation. Three independent hunts (refcount wrap, stale-slot double free, double
finish) each looked promising and each died on a specific defence.

---

## 14. BOTTOM LINE

The reachability question that has been open since §20.5 is **closed**: the JPEG chain's
`IOMemoryDescriptor` is an `IOSurface`-owned **`IOBufferMemoryDescriptor`**, and that class's
`dmaCommandOperation` has **no bound on the `_dmaReferences` increment at all** — the op-3 guard
Apple added in 27.0 GM is not merely skipped, it does not exist on this class. The severity
question is unchanged and still open: the counter must still be driven to `0x10000`, and no
memory-safety consequence has been demonstrated.

> Reachable, defective, unfixed, and now proven to be on the *unguarded* implementation — with the
> consequence still unproven.
