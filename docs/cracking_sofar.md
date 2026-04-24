# gocryptfs GPU Cracking — Hashcat Mode 33200 — Status

## What This Is

A native hashcat GPU module (mode 33200) for cracking gocryptfs-encrypted volumes.
gocryptfs uses scrypt as its KDF, so GPU acceleration is meaningful.
This module reuses hashcat's existing scrypt kernel infrastructure (same as mode 8900)
and adds a custom `_comp` kernel that performs HKDF-Extract → HKDF-Expand → AES-256-GCM.

---

## Files

| File | Purpose |
|------|---------|
| `~/Downloads/hashcat-src/hashcat-7.1.2/src/modules/module_33200.c` | Host-side module (hash decode/encode, salt layout) |
| `~/Downloads/hashcat-src/hashcat-7.1.2/OpenCL/m33200-pure.cl` | GPU kernel (scrypt + HKDF + AES-GCM) |
| `~/Downloads/hashcat-src/hashcat-7.1.2/docs/cracking_sofar.md` | This document |

The working directory for build/run is `~/Downloads/hashcat-src/hashcat-7.1.2/`.
There is also `~/Downloads/hashcat-7.1.2/` (a separate pre-compiled install) — do NOT confuse them.

---

## Hash Format

```
$gocryptfs$N$r$p$<base64_salt>$<base64_encrypted_key>
```

- Salt: 32 raw bytes, base64-encoded
- EncryptedKey: 64 bytes total = nonce(16) + ciphertext(32) + GCM_tag(16), base64-encoded

### Test Hash (password = "onmyown")
```
$gocryptfs$65536$8$1$hwB+hikAXdxJo/klFuyB/5nVVeFtHLIguxCDuD3TCFY$uLiG8704m3pFT77kmDwgQoLp9FJZvPJGRPbx0vnRdn1NjtTExkjDRymZu2qhZr6aXfX5R58+fy7MQ5X9+ATUjw
```

### Target Hash (unknown password)
```
$gocryptfs$65536$8$1$aDR+SmiqZenYznZAfYbxRcbyV8SKYlXuN+MwsxNsYD0$u5fI8G3aFuV5+aSqdY88Qr5mZwp6MTw2tl79VVh8vp6F2bBV1w7JYky7rzAARIJRDgEgZ1xc6WWS6fbdTsNosQ
```

---

## Crypto Chain (Verified Correct in Python)

```
1. scrypt(password, salt_32bytes, N=65536, r=8, p=1, dkLen=32)  →  scrypt_key (32 bytes)

2. HKDF-Extract:
   PRK = HMAC-SHA256(key=\x00*32, data=scrypt_key)

3. HKDF-Expand:
   enc_key = HMAC-SHA256(key=PRK, data="AES-GCM file content encryption\x01")
   (info string = 31 ASCII bytes + 0x01 counter byte = 32 bytes total)

4. AES-256-GCM:
   - nonce = EncryptedKey[0:16]   (16 bytes → J0 via GHASH path, NOT 12-byte shortcut)
   - ct    = EncryptedKey[16:48]  (32 bytes)
   - AD    = \x00\x00\x00\x00\x00\x00\x00\x00  (8 zero bytes)
   - tag_computed = GHASH(subkey, AD, ct) XOR AES256(J0, key=enc_key)
   - Compare tag_computed against EncryptedKey[48:64]
```

---

## Reference Values for "onmyown" Test Case

All values computed from Python (pyscrypt + cryptography libraries).

```
scrypt salt (hex):  87007e8629005ddc49a3f92516ec81ff99d555e16d1cb220bb1083b83dd30856
scrypt_key (hex):   fa6d57e37623d189baa80854bf6cbf5fbcc2cbdba3e918ae1af3ef315c78f64b

scrypt_key as LE u32 (old kernel format, now unused):
  [0xe3576dfa, 0x89d12376, 0x5408a8ba, 0x5fbf6cbf,
   0xdbcbc2bc, 0xae18e9a3, 0x31eff31a, 0x4bf6785c]

scrypt_key as BE u32 (current kernel format, ctx.opad.h after inline PBKDF2):
  [0xfa6d57e3, 0x7623d189, 0xbaa80854, 0xbf6cbf5f,
   0xbcc2cbdb, 0xa3e918ae, 0x1af3ef31, 0x5c78f64b]

PRK (BE u32):
  [0x415e72e5, 0xfc148a5c, 0xd7044854, 0x76ed2251,
   0x81a47dd4, 0x1e996b86, 0x18196e32, 0xf06d9a85]

enc_key (BE u32):
  [0x30581f74, 0xf0adc891, 0x6261663b, 0x32b6721a,
   0xa7b89994, 0xf6ab9070, 0x0ce44344, 0xf5359bea]

H (AES-GCM subkey, BE u32):  [0xf3167191, 0xcc0bbf15, 0xb48179a4, 0x52da1048]
J0 (BE u32):                  [0xc1a5cfbd, 0xcbc48808, 0xbe55dcfe, 0x68ac2504]
E(J0) (BE u32):               [0x8aa48455, 0x06c4bc1d, 0xb8fd5784, 0x4b008835]
GHASH (BE u32):               [0xd7517d12, 0x99fac333, 0x74bec279, 0xb3045cba]
Expected tag (BE u32):        [0x5df5f947, 0x9f3e7f2e, 0xcc4395fd, 0xf804d48f]
```

---

## Salt Buffer Layout in module_33200.c

`module_hash_decode` parses the hash and fills:

```
salt_buf[0..7]   = scrypt salt (32 bytes) — raw memcpy, no byte-swap
                   (sha256_hmac_update_global_swap in scrypt kernel handles LE→BE)

salt_buf[8..11]  = nonce (16 bytes) — byte_swap_32 applied → stored as BE u32
salt_buf[12..19] = ciphertext (32 bytes) — byte_swap_32 applied → stored as BE u32
digest_buf[0..3] = GCM tag (16 bytes) — byte_swap_32 applied → stored as BE u32

salt_len         = 32 (the scrypt salt length, NOT SCRYPT_SZ)
```

**Critical:** `byte_swap_32` converts LE (x86 memcpy result) to BE.
So raw tag bytes `[5d f5 f9 47 ...]` → memcpy gives u32 = 0x47f9f55d (LE) →
byte_swap_32 → digest_buf[0] = 0x5df5f947 (BE). ✓

**How to build debug test hashes from Python:**
```python
import base64, struct

# To test if r0..r3 == [A, B, C, D] (all BE u32):
tag_bytes = struct.pack('>4I', A, B, C, D)
enc_key_blob = b'\x00'*48 + tag_bytes   # zero nonce+ct, real tag at end
salt_b64 = 'hwB+hikAXdxJo/klFuyB/5nVVeFtHLIguxCDuD3TCFY'  # real test salt
enc_b64 = base64.b64encode(enc_key_blob).decode().rstrip('=')
print(f'$gocryptfs$65536$8$1${salt_b64}${enc_b64}')
```

The kernel outputs r0..r3 and hashcat compares them against digest_buf[0..3].
If the values match, the hash "cracks" with password "onmyown".

---

## Build and Test Commands

**ALWAYS run from the source directory:**
```bash
cd ~/Downloads/hashcat-src/hashcat-7.1.2
```

**Build (required after editing .c files; not needed for .cl-only changes):**
```bash
make
```

**Clear kernel cache (REQUIRED after every .cl edit):**
```bash
rm -f ~/Downloads/hashcat-src/hashcat-7.1.2/kernels/m33200*.kernel
```
If you forget this, hashcat will use the OLD compiled kernel and you'll see stale results.

**Clear potfile (so hashcat doesn't skip already-found hashes):**
```bash
echo "" > ~/Downloads/hashcat-src/hashcat-7.1.2/hashcat.potfile
```

**Run test (known password "onmyown"):**
```bash
echo "onmyown" > /tmp/test_wordlist.txt
echo '$gocryptfs$65536$8$1$hwB+hikAXdxJo/klFuyB/5nVVeFtHLIguxCDuD3TCFY$uLiG8704m3pFT77kmDwgQoLp9FJZvPJGRPbx0vnRdn1NjtTExkjDRymZu2qhZr6aXfX5R58+fy7MQ5X9+ATUjw' > /tmp/test.hash

cd ~/Downloads/hashcat-src/hashcat-7.1.2
rm -f kernels/m33200*.kernel
echo "" > hashcat.potfile
timeout 120 ./hashcat -m 33200 /tmp/test.hash /tmp/test_wordlist.txt --self-test-disable -d 1
```

**Expected success output:** `Status: Cracked`, `Recovered: 1/1`

**`--self-test-disable`** is required because no self-test hash is wired up yet in the module.
**`-d 1`** uses only GPU device 1 (avoids OpenCL device enumeration issues on this machine).

---

## Source Files Consulted (for reference)

```
OpenCL/inc_hash_sha256.cl      — SHA256, sha256_hmac_*, sha256_update_64, etc.
OpenCL/inc_hash_scrypt.cl      — scrypt_pbkdf2_*, scrypt_blockmix_*, SCRYPT_SZ def
OpenCL/inc_hash_scrypt.h       — SCRYPT_SZ = 128*r*p (bytes), GET_SCRYPT_SZ macro
OpenCL/inc_cipher_aes.cl       — AES256_set_encrypt_key, AES256_encrypt
OpenCL/inc_cipher_aes-gcm.cl   — AES_GCM_Init, AES_GCM_Prepare_J0, AES_GCM_GHASH,
                                  AES_GCM_GCTR, AES_GCM_ghash, AES_GCM_gctr
OpenCL/inc_vendor.h            — DECLSPEC = HC_INLINE (functions are always inlined)
OpenCL/m08900-pure.cl          — Reference scrypt mode (init/loop/comp pattern)
src/modules/scrypt_common.c    — SCRYPT_SZ comment, JIT build options
src/modules/module_08900.c     — Reference host module for scrypt
```

---

## Key Insights / Gotchas Discovered

### 1. SCRYPT_SZ is in BYTES, not u32 words
`SCRYPT_SZ = 128 * r * p` = 1024 bytes for r=8, p=1.
Passed as `salt_len` to `sha256_hmac_update_global_swap` — which expects bytes. ✓

### 2. sha256_update always reads 16 u32s regardless of len
`sha256_update` and `sha256_update_swap` unconditionally read `w[0..15]` (64 bytes)
even when `len=32`. Any input array passed to these must be zero-padded to 16 u32s.
Same for `sha256_hmac_init` (reads all 16 words of key in ≤64 branch).
Failing to zero-pad causes SHA256 to process garbage bytes → wrong hash.

### 3. REAL_SHM must load before GID check
AES S-box shared memory (te0..te4) is loaded by ALL threads in a workgroup cooperatively.
If you put `if (gid >= GID_CNT) return;` BEFORE the shared memory load,
with only 1 active password most threads exit early and the S-boxes never get filled.
Result: AES produces garbage. The REAL_SHM loading block MUST come before the GID check.

### 4. scrypt_pbkdf2_ggp creates an internal sha256_hmac_ctx_t
`sha256_hmac_ctx_t` = 50 u32s = 200 bytes.
When `scrypt_pbkdf2_ggp` is inlined (DECLSPEC = always_inline), its internal ctx
adds 50 u32s to the already-large register footprint of the comp kernel.
Total register pressure exceeds GPU limits → register spilling → memory corruption.
**Fix:** Inline the PBKDF2 finalization manually, reusing a single ctx for all three HMACs.

### 5. AES256_set_encrypt_key byte-swaps its input
```c
ukey_s[0] = hc_swap32_S(ukey[0]);  // BE → LE before key schedule
```
So pass enc_key as BE u32 (as SHA256 naturally produces) — no manual swapping needed.

### 6. sha256_hmac_final result is in ctx.opad.h[0..7]
After `sha256_hmac_final(&ctx)`, the HMAC output is in `ctx.opad.h[0..7]` as BE u32.
These can be used directly for the next HMAC init via `sha256_hmac_init_64`.

### 7. PBKDF2 block counter representation
In `scrypt_pbkdf2_body_pp`, the counter is `w0[0] = j = 1` (u32 = 0x00000001).
SHA256's internal representation treats u32 as BE, so this is bytes `00 00 00 01`. ✓
In the inline version: `u32 cb[4] = {1, 0, 0, 0}` passed to `sha256_hmac_update_64`. ✓

### 8. HKDF-Extract: use sha256_hmac_update_64 with BE scrypt key directly
The scrypt PBKDF2 output in `ctx.opad.h` is already BE u32.
The HKDF-Extract HMAC input is the scrypt key bytes.
Feeding `ctx.opad.h[0..7]` directly via `sha256_hmac_update_64` is correct —
no swap needed because SHA256 processes BE u32 words as the right byte sequence.
(The old approach: write LE u32 to buffer, then sha256_hmac_update_swap swaps back to BE —
same result, but required larger intermediate arrays.)

### 9. AES-GCM nonce is 16 bytes → uses GHASH path for J0
`AES_GCM_Prepare_J0(nonce, 16, subkey, J0)` — the `16` triggers the GHASH path
(not the 12-byte shortcut). This is correct for gocryptfs.

### 10. Digest encoding for debug test hashes
When outputting `r0 = some_BE_u32_value`, build the debug hash like:
```python
tag_bytes = struct.pack('>4I', r0_expected, r1_expected, r2_expected, r3_expected)
```
The `>4I` packs as big-endian, so the raw bytes match what module_hash_decode
expects when it does `memcpy + byte_swap_32`. Using `<4I` (little-endian) gives
the wrong digest and the hash won't crack even if values are correct.

---

## What Works (Confirmed Cracking)

| Test | Result |
|------|--------|
| Mode 8900 (raw scrypt) with same salt/password | CRACKED ✓ |
| Hardcoded scrypt_key → HKDF → AES-GCM | CRACKED ✓ |
| Hardcoded enc_key → AES-GCM | CRACKED ✓ |
| Inline PBKDF2 → correct scrypt_key (BE u32) | CRACKED ✓ |
| Inline PBKDF2 → HKDF-Extract → correct PRK | CRACKED ✓ |
| Inline PBKDF2 → HKDF-Extract → HKDF-Expand → correct enc_key[0..3] | CRACKED ✓ |
| Full chain (all steps + AES-GCM) | **EXHAUSTED ✗** |

---

## Current Bug: Full Chain Still Fails

### Precise Description
Every individual step is verified correct:
- Inline PBKDF2 produces correct scrypt_key ✓
- HKDF-Extract produces correct PRK ✓  
- HKDF-Expand produces correct enc_key[0..3] (and [4..7] from earlier tests) ✓
- AES-GCM with hardcoded enc_key cracks ✓
- enc_key is correct even with `key[60]` declared before HKDF ✓

Yet when the full chain runs (PBKDF2 → HKDF → AES-GCM in one comp kernel invocation),
the hash exhausts.

### Hypothesis
The bug is in the transition from HKDF-Expand to AES_GCM_Init.
Specifically, `AES_GCM_Init` calls `AES256_set_encrypt_key` which expands
`ctx.opad.h` (enc_key, 8 words) into `key[60]` (60 u32 = 240 bytes round key schedule).

Even though `ctx.opad.h` is correct immediately before AES_GCM_Init (confirmed by
the enc_key debug test which exits early and cracks), something goes wrong when
the full AES-GCM pipeline runs.

Possible explanations:
- **Memory aliasing:** `key[60]` in GPU register spill space overlaps with
  `ctx.opad.h` or another live variable. AES_GCM_Init reads enc_key correctly,
  then writes key[60], corrupting something needed later.
- **AES subkey corruption:** After AES_GCM_Init, `subkey[4]` or `J0[4]` is wrong
  due to register pressure.
- **nonce loading from salt_buf:** The nonce words from `salt_bufs[SALT_POS_HOST].salt_buf[8..11]`
  may be getting wrong values in the full-chain context.

### Next Debugging Steps

**Step A: Verify subkey after AES_GCM_Init**
Expected subkey (H, BE u32): `[0xf3167191, 0xcc0bbf15, 0xb48179a4, 0x52da1048]`

Note: `AES256_set_encrypt_key` byte-swaps its input (BE→LE) before key expansion.
Then `AES256_encrypt(key, zeros, subkey)` produces H. The resulting subkey may be
in a different byte order depending on how AES_GCM_ghash uses it.
Check `inc_cipher_aes-gcm.cl` AES_GCM_gf_mult to determine expected byte order.

Build a test hash for `subkey[0]`:
```python
tag_bytes = struct.pack('>4I', 0xf3167191, 0xcc0bbf15, 0xb48179a4, 0x52da1048)
```
Then output `r0..r3 = subkey[0..3]` after AES_GCM_Init and compare.

**Step B: Verify nonce load from salt_buf**
Expected nonce in salt_buf[8..11] (BE u32): check by outputting
`r0 = salt_bufs[SALT_POS_HOST].salt_buf[8]` etc. directly.

**Step C: Verify J0 after Prepare_J0**
Expected J0 (BE u32): `[0xc1a5cfbd, 0xcbc48808, 0xbe55dcfe, 0x68ac2504]`

**Step D: Verify S (GHASH output) after AES_GCM_GHASH**
Expected GHASH (BE u32): `[0xd7517d12, 0x99fac333, 0x74bec279, 0xb3045cba]`

**Step E: Alternative — try splitting AES_GCM_Init away**
Instead of `AES_GCM_Init(ctx.opad.h, ...)`, manually save enc_key to 8 scalar
variables (like sk0..sk7 pattern), zero ctx entirely, THEN build a fresh u32[8]
array for AES_GCM_Init. This forces the compiler to see ctx as dead before AES.

---

## Current State of m33200-pure.cl (as of this writing)

The kernel currently has a DEBUG version that:
1. Runs full inline PBKDF2 + HKDF-Extract + HKDF-Expand
2. Declares `key[60]` and `subkey[4]` early (before HKDF) to test aliasing
3. **Exits early** outputting `enc_key[0..3]` as `r0..r3` (for debugging)
4. Does NOT call AES (the AES block is absent from the current file)

To restore the full chain, add back the AES-GCM step (Step 4) after the HKDF
and change `r0..r3 = tag[0..3]` instead of `ctx.opad.h[0..3]`.

The intended final form of the comp kernel is in this document under the section below.

---

## Intended Final Kernel Structure (m33200_comp)

```c
// 1. AES S-box shared memory (BEFORE GID check)
#ifdef REAL_SHM
  LOCAL_VK u32 s_te0[256]; ... (fill from te0..te4, SYNC_THREADS)
#else
  CONSTANT_AS u32a *s_te0 = te0; ...
#endif

if (gid >= GID_CNT) return;

// 2. Scrypt finalization (inline PBKDF2)
scrypt_blockmix_out(tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

u32 key[60] = {0}; u32 subkey[4] = {0};  // declare AES arrays early

sha256_hmac_ctx_t ctx;
sha256_hmac_init_global_swap(&ctx, pws[gid].i, pws[gid].pw_len);
sha256_hmac_update_global_swap(&ctx, tmps[gid].in, SCRYPT_SZ);
u32 z4[4]={0,0,0,0}; u32 cb[4]={1,0,0,0};
sha256_hmac_update_64(&ctx, cb, z4, z4, z4, 4);
sha256_hmac_final(&ctx);
// ctx.opad.h[0..7] = scrypt_key (BE u32)

// 3. HKDF-Extract
u32 sk0=ctx.opad.h[0]; ... u32 sk7=ctx.opad.h[7];
sha256_hmac_init_64(&ctx, z4, z4, z4, z4);
u32 sk_lo[4]={sk0,sk1,sk2,sk3}; u32 sk_hi[4]={sk4,sk5,sk6,sk7};
sha256_hmac_update_64(&ctx, sk_lo, sk_hi, z4, z4, 32);
sha256_hmac_final(&ctx);
// ctx.opad.h[0..7] = PRK (BE u32)

// 4. HKDF-Expand
u32 prk0=ctx.opad.h[0]; ... u32 prk7=ctx.opad.h[7];
u32 prk_lo[4]={prk0,prk1,prk2,prk3}; u32 prk_hi[4]={prk4,prk5,prk6,prk7};
sha256_hmac_init_64(&ctx, prk_lo, prk_hi, z4, z4);
u32 info_lo[4]={0x4145532d,0x47434d20,0x66696c65,0x20636f6e};
u32 info_hi[4]={0x74656e74,0x20656e63,0x72797074,0x696f6e01};
sha256_hmac_update_64(&ctx, info_lo, info_hi, z4, z4, 32);
sha256_hmac_final(&ctx);
// ctx.opad.h[0..7] = enc_key (BE u32)

// 5. AES-256-GCM tag verification
AES_GCM_Init(ctx.opad.h, 256, key, subkey, s_te0..s_te4);

u32 nonce[4]; nonce[0..3] = salt_bufs[SALT_POS_HOST].salt_buf[8..11];
u32 J0[4]={0};
AES_GCM_Prepare_J0(nonce, 16, subkey, J0);

u32 ct[8]; ct[0..7] = salt_bufs[SALT_POS_HOST].salt_buf[12..19];
u32 ad[2]={0,0}; u32 S[4]={0};
AES_GCM_GHASH(subkey, ad, 8, ct, 32, S);

u32 tag[4]={0};
AES_GCM_GCTR(key, J0, S, 16, tag, s_te0..s_te4);

r0=tag[0]; r1=tag[1]; r2=tag[2]; r3=tag[3];
#include COMPARE_M
```

---

## Python Reference Script (to verify full chain)

```python
#!/usr/bin/env python3
"""Verify gocryptfs crypto chain for test hash (password = 'onmyown')"""
import base64, hashlib, hmac, struct
import pyscrypt  # pip install pyscrypt

# Parse test hash
salt_b64 = 'hwB+hikAXdxJo/klFuyB/5nVVeFtHLIguxCDuD3TCFY'
enc_b64  = 'uLiG8704m3pFT77kmDwgQoLp9FJZvPJGRPbx0vnRdn1NjtTExkjDRymZu2qhZr6aXfX5R58+fy7MQ5X9+ATUjw'

# Pad base64 to multiple of 4
def b64d(s): return base64.b64decode(s + '=='*((-len(s))%4))

salt = b64d(salt_b64)          # 32 bytes
enc  = b64d(enc_b64)            # 64 bytes
nonce = enc[0:16]
ct    = enc[16:48]
tag   = enc[48:64]

password = b'onmyown'

# Step 1: scrypt
scrypt_key = pyscrypt.hash(password, salt, 65536, 8, 1, 32)
print(f'scrypt_key: {scrypt_key.hex()}')

# Step 2: HKDF-Extract
prk = hmac.new(b'\x00'*32, scrypt_key, hashlib.sha256).digest()
print(f'PRK:        {prk.hex()}')

# Step 3: HKDF-Expand
info = b'AES-GCM file content encryption\x01'
enc_key = hmac.new(prk, info, hashlib.sha256).digest()
print(f'enc_key:    {enc_key.hex()}')

# Step 4: AES-256-GCM tag verification
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = AESGCM(enc_key)
try:
    pt = aesgcm.decrypt(nonce, ct + tag, b'\x00'*8)
    print(f'DECRYPTED: {pt.hex()}')
except Exception as e:
    print(f'Decrypt failed: {e}')
```

---

## Register Pressure Notes

The `m33200_comp` kernel is register-intensive. On an NVIDIA GPU with 256 VGPRs per thread:

| Variable | Size (u32s) | Notes |
|----------|------------|-------|
| sha256_hmac_ctx_t ctx | 50 | ipad + opad, each 25 u32 |
| key[60] | 60 | AES-256 round key schedule |
| subkey[4] | 4 | AES-GCM H value |
| sk0..sk7 | 8 | scalar saves of scrypt_key |
| prk0..prk7 | 8 | scalar saves of PRK |
| z4, cb, sk_lo/hi, prk_lo/hi, info_lo/hi | ~24 | temporaries |
| nonce, J0, ct, ad, S, tag | 26 | AES-GCM working vars |

**Peak usage ~180 u32s** — tight but should fit without spilling.

The OLD approach (using `scrypt_pbkdf2_ggp` + `scrypt_key[16]` + `zeros[16]` + `prk_buf[16]` + `info[16]`)
added ~50 (internal ctx) + 48 (large arrays) = ~98 extra u32s → total ~278 u32s → causes spilling → corruption.

The NEW inline approach eliminates ~98 u32s by:
- Not calling `scrypt_pbkdf2_ggp` (saves its 50-u32 internal ctx)
- Using scalar sk0..sk7 instead of scrypt_key[16] (saves 8 u32s)
- Using z4[4] reused for zeros instead of zeros[16] (saves 12 u32s)
- Using prk0..prk7 scalars instead of prk_buf[16] (saves 8 u32s)
- Using info_lo/hi[4] instead of info[16] (saves 8 u32s)
