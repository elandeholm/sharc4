typedef struct
{
  sha256_context sha256_ctx;
  uint8 ki[64], ko[64];
}
sha256_hmac_context;

void sha256_hmac_starts(sha256_hmac_context *hmac_ctx, const uint8 key[32]);
void sha256_hmac_update(sha256_hmac_context *hmac_ctx, const uint8 *input, uint32 length);
void sha256_hmac_finish(sha256_hmac_context *hmac_ctx, uint8 hmac[32]);
void sha256_hmac_destruct(sha256_hmac_context *hmac_ctx);
