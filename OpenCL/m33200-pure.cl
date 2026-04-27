/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

KERNEL_FQ KERNEL_FA void m33200_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m33200_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m33200_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m33200_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // Step 3 of scrypt RFC 7914: PBKDF2-HMAC-SHA256(password, B', 1, 32) -> scrypt_key
  u32 scrypt_key[8];
  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, scrypt_key, 32);

  // HKDF-Extract: HMAC-SHA256(key=0x00*32, data=scrypt_key) -> PRK
  u32 enc_key[8];

  {
    sha256_hmac_ctx_t ctx;

    u32 zk0[4] = {0, 0, 0, 0};
    u32 zk1[4] = {0, 0, 0, 0};
    u32 z4[4]  = {0, 0, 0, 0};

    // scrypt_key is stored as LE u32 (from pbkdf2_body_pp hc_swap32_S).
    // sha256_hmac_update_64 expects BE u32 (SHA256 internal format).
    u32 sk_be[8];
    sk_be[0] = hc_swap32_S (scrypt_key[0]); sk_be[1] = hc_swap32_S (scrypt_key[1]);
    sk_be[2] = hc_swap32_S (scrypt_key[2]); sk_be[3] = hc_swap32_S (scrypt_key[3]);
    sk_be[4] = hc_swap32_S (scrypt_key[4]); sk_be[5] = hc_swap32_S (scrypt_key[5]);
    sk_be[6] = hc_swap32_S (scrypt_key[6]); sk_be[7] = hc_swap32_S (scrypt_key[7]);

    sha256_hmac_init_64 (&ctx, zk0, zk1, z4, z4);
    sha256_hmac_update_64 (&ctx, sk_be, sk_be + 4, z4, z4, 32);
    sha256_hmac_final (&ctx);

    u32 prk[8];
    prk[0] = ctx.opad.h[0]; prk[1] = ctx.opad.h[1];
    prk[2] = ctx.opad.h[2]; prk[3] = ctx.opad.h[3];
    prk[4] = ctx.opad.h[4]; prk[5] = ctx.opad.h[5];
    prk[6] = ctx.opad.h[6]; prk[7] = ctx.opad.h[7];

    // HKDF-Expand: HMAC-SHA256(key=PRK, data="AES-GCM file content encryption\x01") -> enc_key
    u32 info0[4] = {0x4145532d, 0x47434d20, 0x66696c65, 0x20636f6e};
    u32 info1[4] = {0x74656e74, 0x20656e63, 0x72797074, 0x696f6e01};
    sha256_hmac_init_64 (&ctx, prk, prk + 4, z4, z4);
    sha256_hmac_update_64 (&ctx, info0, info1, z4, z4, 32);
    sha256_hmac_final (&ctx);

    enc_key[0] = ctx.opad.h[0]; enc_key[1] = ctx.opad.h[1];
    enc_key[2] = ctx.opad.h[2]; enc_key[3] = ctx.opad.h[3];
    enc_key[4] = ctx.opad.h[4]; enc_key[5] = ctx.opad.h[5];
    enc_key[6] = ctx.opad.h[6]; enc_key[7] = ctx.opad.h[7];
  }

  // AES-256-GCM verification
  {
    u32 key[60] = {0};
    u32 subkey[4] = {0};
    AES_GCM_Init (enc_key, 256, key, subkey, s_te0, s_te1, s_te2, s_te3, s_te4);

    // nonce stored at salt_buf[16..19] (bytes 0-15 of EncryptedKey, big-endian u32)
    u32 nonce[4];
    nonce[0] = salt_bufs[SALT_POS_HOST].salt_buf[16];
    nonce[1] = salt_bufs[SALT_POS_HOST].salt_buf[17];
    nonce[2] = salt_bufs[SALT_POS_HOST].salt_buf[18];
    nonce[3] = salt_bufs[SALT_POS_HOST].salt_buf[19];

    u32 J0[4] = {0};
    AES_GCM_Prepare_J0 (nonce, 16, subkey, J0);

    // additional data: 8 zero bytes (blockNo=0, fileID=nil)
    u32 ad[2] = {0, 0};
    u32 S[4] = {0};
    // ciphertext at salt_buf[20..27] (bytes 16-47 of EncryptedKey, 32 bytes)
    AES_GCM_GHASH_GLOBAL (subkey, ad, 8, salt_bufs[SALT_POS_HOST].salt_buf + 20, 32, S);

    u32 tag[4] = {0};
    AES_GCM_GCTR (key, J0, S, 16, tag, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = tag[0];
    const u32 r1 = tag[1];
    const u32 r2 = tag[2];
    const u32 r3 = tag[3];

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
