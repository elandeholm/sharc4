typedef struct
{
  int i, j;
  int sbox[256];
} rc4ctx_t;

void rc4_parameters(int _N, int _skip);
void rc4_setkey(rc4ctx_t *rc4c, uint8 *key, int len);
void rc4_destruct(rc4ctx_t *rc4c);
void rc4_crypt(rc4ctx_t *rc4c, const uint8 *src, uint8 *dst, int len);
void rc4_crypt_inplace(rc4ctx_t *rc4c, uint8 *data, int len);
