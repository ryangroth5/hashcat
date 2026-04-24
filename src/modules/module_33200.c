/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Mode 33200 - gocryptfs
 *
 * Chain: scrypt -> HKDF-SHA256 -> AES-256-GCM tag verify
 *
 * Hash format:
 *   $gocryptfs$N$r$p$<base64_salt>$<base64_encrypted_key>
 *
 * The 64-byte EncryptedKey encodes:
 *   bytes  0-15: AES-GCM nonce (stored in salt_buf[8..11])
 *   bytes 16-47: AES-GCM ciphertext (stored in salt_buf[12..19])
 *   bytes 48-63: AES-GCM authentication tag (stored in digest_buf[0..3])
 *
 * HKDF parameters:
 *   Extract: HMAC-SHA256(key=zeros_32, data=scrypt_key)     -> PRK
 *   Expand:  HMAC-SHA256(key=PRK, data=info || 0x01)        -> enc_key
 *   info = "AES-GCM file content encryption"
 *   AD   = 0x0000000000000000 (blockNo=0, fileID=nil)
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "gocryptfs";
static const u64   KERN_TYPE      = 33200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "onmyown";
static const char *ST_HASH        = "$gocryptfs$65536$8$1$hwB+hikAXdxJo/klFuyB/5nVVeFtHLIguxCDuD3TCFY$uLiG8704m3pFT77kmDwgQoLp9FJZvPJGRPbx0vnRdn1NjtTExkjDRymZu2qhZr6aXfX5R58+fy7MQ5X9+ATUjw";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const char *SIGNATURE_GOCRYPTFS = "gocryptfs";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));

  // Format: $gocryptfs$N$r$p$<b64_salt>$<b64_enc_key>
  // Tokens: [0]="" [1]="gocryptfs" [2]=N [3]=r [4]=p [5]=b64salt [6]=b64enckey

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_GOCRYPTFS;

  // token[0]: empty prefix before leading $
  token.sep[0]     = '$';
  token.len[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  // token[1]: signature "gocryptfs"
  token.sep[1]     = '$';
  token.len[1]     = 9;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // token[2]: N
  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 7;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // token[3]: r
  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 4;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // token[4]: p
  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 4;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  // token[5]: base64 scrypt salt (32 bytes -> 43 chars without padding)
  token.sep[5]     = '$';
  token.len_min[5] = 43;
  token.len_max[5] = 44;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // token[6]: base64 EncryptedKey (64 bytes -> 86 chars without padding)
  token.sep[6]     = '$';
  token.len_min[6] = 86;
  token.len_max[6] = 88;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // scrypt params
  salt->scrypt_N = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  if (salt->scrypt_N % 1024) return (PARSER_SALT_VALUE);

  // Decode scrypt salt (32 bytes) into salt_buf[0..7]
  u8 tmp_buf[128] = { 0 };
  const int salt_len = base64_decode (base64_to_int, token.buf[5], token.len[5], tmp_buf);
  if (salt_len != 32) return (PARSER_SALT_LENGTH);
  memcpy (salt->salt_buf, tmp_buf, 32);
  salt->salt_len = 32;

  // Decode EncryptedKey (64 bytes) into tmp_buf
  memset (tmp_buf, 0, sizeof (tmp_buf));
  const int enc_len = base64_decode (base64_to_int, token.buf[6], token.len[6], tmp_buf);
  if (enc_len != 64) return (PARSER_HASH_LENGTH);

  // Layout in salt_buf beyond the scrypt salt:
  //   salt_buf[8..11]  = nonce   (bytes  0-15 of EncryptedKey)
  //   salt_buf[12..19] = ct      (bytes 16-47 of EncryptedKey)
  // The GCM tag (bytes 48-63) goes into digest_buf[0..3]
  //
  // AES-GCM functions in OpenCL expect big-endian u32.
  // memcpy from u8 to u32 on x86 produces little-endian, so we byte-swap.

  memcpy (salt->salt_buf + 8,  tmp_buf,      16); // nonce
  memcpy (salt->salt_buf + 12, tmp_buf + 16, 32); // ciphertext

  // Byte-swap nonce and ct to big-endian u32 for AES-GCM
  for (int i = 8; i < 20; i++)
    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);

  // GCM tag -> digest (stored as big-endian u32 to match AES-GCM output)
  memcpy (digest, tmp_buf + 48, 16);
  for (int i = 0; i < 4; i++)
    digest[i] = byte_swap_32 (digest[i]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  // Reconstruct the 64-byte EncryptedKey from salt_buf + digest_buf
  // salt_buf and digest are stored as big-endian u32 — swap back to raw bytes.
  u32 tmp32[20];
  for (int i = 0; i < 12; i++) tmp32[i] = byte_swap_32 (salt->salt_buf[8 + i]);

  const u32 *dg = (const u32 *) digest_buf;
  u32 tag32[4];
  for (int i = 0; i < 4; i++) tag32[i] = byte_swap_32 (dg[i]);

  u8 enc_key[64];
  memcpy (enc_key,      tmp32,      16); // nonce
  memcpy (enc_key + 16, tmp32 + 4,  32); // ciphertext
  memcpy (enc_key + 48, tag32,      16); // tag

  char base64_salt[64]    = { 0 };
  char base64_enc_key[96] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, 32,       (u8 *) base64_salt);
  base64_encode (int_to_base64, enc_key,                     64, (u8 *) base64_enc_key);

  // Strip trailing padding '='
  int salt_b64_len = (int) strlen (base64_salt);
  while (salt_b64_len > 0 && base64_salt[salt_b64_len - 1] == '=') salt_b64_len--;
  base64_salt[salt_b64_len] = 0;

  int enc_b64_len = (int) strlen (base64_enc_key);
  while (enc_b64_len > 0 && base64_enc_key[enc_b64_len - 1] == '=') enc_b64_len--;
  base64_enc_key[enc_b64_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "$%s$%u$%u$%u$%s$%s",
    SIGNATURE_GOCRYPTFS,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    base64_salt,
    base64_enc_key);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
