#include <string.h> /* memset */
#include "sha256.h"
#include "sha256_hmac.h"

static void sha256_hmac_expand_key(sha256_hmac_context *hmac_ctx, const uint8 key[32])
{
  int i;

  for(i = 0; i < 32; ++i)
    {
      hmac_ctx->ki[i] = key[i] ^ 0x5c;
      hmac_ctx->ko[i] = key[i] ^ 0x36;
    }
  for(; i < 64; ++i)
    {
      hmac_ctx->ki[i] = 0x5c;
      hmac_ctx->ko[i] = 0x36;
    }
}

void sha256_hmac_starts(sha256_hmac_context *hmac_ctx, const uint8 key[32])
{
  /* start inner SHA256 */

  sha256_hmac_expand_key(hmac_ctx, key);
  sha256_starts(&hmac_ctx->sha256_ctx);

  sha256_update(&hmac_ctx->sha256_ctx, hmac_ctx->ki, sizeof(hmac_ctx->ki));
}

void sha256_hmac_update(sha256_hmac_context *hmac_ctx, const uint8 *input, uint32 length)
{
  sha256_update(&hmac_ctx->sha256_ctx, (uint8 *)input, length);
}

void sha256_hmac_finish(sha256_hmac_context *hmac_ctx, uint8 hmac[32])
{
  uint8 hash[32];

  /* finish inner SHA256 to tmp hash */

  sha256_finish(&hmac_ctx->sha256_ctx, hash);

  /* start outer SHA256 */

  sha256_starts(&hmac_ctx->sha256_ctx);
  sha256_update(&hmac_ctx->sha256_ctx, hmac_ctx->ko, sizeof(hmac_ctx->ko));
  sha256_update(&hmac_ctx->sha256_ctx, hash, sizeof(hash));

  /* finish outer SHA256 to hmac */

  sha256_finish(&hmac_ctx->sha256_ctx, hmac);

  memset(hash, 0, sizeof(hash));
}

/* for the truly paranoid */

void sha256_hmac_destruct(sha256_hmac_context *hmac_ctx)
{
  memset(hmac_ctx, 0, sizeof(*hmac_ctx));
}
