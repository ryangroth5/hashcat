/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Mode 33200 - gocryptfs
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

  /**
   * AES shared memory (must be set up before GID check)
   */

  #ifdef REAL_SHM

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

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  /* Declare AES arrays early so compiler allocates them separately from HKDF vars */
  u32 key[60] = { 0 };
  u32 subkey[4] = { 0 };

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha256_hmac_update_global_swap (&ctx, tmps[gid].in, SCRYPT_SZ);

  u32 z4[4] = { 0, 0, 0, 0 };
  u32 cb[4] = { 1, 0, 0, 0 };
  sha256_hmac_update_64 (&ctx, cb, z4, z4, z4, 4);
  sha256_hmac_final (&ctx);
  /* ctx.opad.h[0..7] = scrypt key (BE u32) */

  u32 sk0 = ctx.opad.h[0]; u32 sk1 = ctx.opad.h[1];
  u32 sk2 = ctx.opad.h[2]; u32 sk3 = ctx.opad.h[3];
  u32 sk4 = ctx.opad.h[4]; u32 sk5 = ctx.opad.h[5];
  u32 sk6 = ctx.opad.h[6]; u32 sk7 = ctx.opad.h[7];

  sha256_hmac_init_64 (&ctx, z4, z4, z4, z4);
  u32 sk_lo[4] = { sk0, sk1, sk2, sk3 };
  u32 sk_hi[4] = { sk4, sk5, sk6, sk7 };
  sha256_hmac_update_64 (&ctx, sk_lo, sk_hi, z4, z4, 32);
  sha256_hmac_final (&ctx);
  /* ctx.opad.h[0..7] = PRK (BE u32) */

  u32 prk0 = ctx.opad.h[0]; u32 prk1 = ctx.opad.h[1];
  u32 prk2 = ctx.opad.h[2]; u32 prk3 = ctx.opad.h[3];
  u32 prk4 = ctx.opad.h[4]; u32 prk5 = ctx.opad.h[5];
  u32 prk6 = ctx.opad.h[6]; u32 prk7 = ctx.opad.h[7];

  u32 prk_lo[4] = { prk0, prk1, prk2, prk3 };
  u32 prk_hi[4] = { prk4, prk5, prk6, prk7 };
  sha256_hmac_init_64 (&ctx, prk_lo, prk_hi, z4, z4);

  u32 info_lo[4] = { 0x4145532d, 0x47434d20, 0x66696c65, 0x20636f6e };
  u32 info_hi[4] = { 0x74656e74, 0x20656e63, 0x72797074, 0x696f6e01 };
  sha256_hmac_update_64 (&ctx, info_lo, info_hi, z4, z4, 32);
  sha256_hmac_final (&ctx);
  /* ctx.opad.h[0..7] = enc_key (BE u32) */

  /* DEBUG: output enc_key[0..3] before AES, with key[60] declared early */
  const u32 r0 = ctx.opad.h[0];
  const u32 r1 = ctx.opad.h[1];
  const u32 r2 = ctx.opad.h[2];
  const u32 r3 = ctx.opad.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
