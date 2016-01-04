#include <string.h>
#include "sha256.h" /* provides uint8 */
#include "rc4.h"

/* number of times to iterate the key setup loop */

static int N = 1;

/* how many initial keystream bytes to skip */

static int skip = 0;

static uint8 rc4_stream(rc4ctx_t *rc4c)
{
  int ti, tj;

  rc4c->i = (rc4c->i + 1) & 0xff;
  ti = rc4c->sbox[rc4c->i];
  rc4c->j = (rc4c->j + ti) & 0xff;
  rc4c->sbox[rc4c->i] = tj = rc4c->sbox[rc4c->j];
  rc4c->sbox[rc4c->j] = ti;
  
  return (ti + tj) & 0xff;
}

void rc4_parameters(int _N, int _skip)
{
  N = _N;
  skip = _skip;
}

void rc4_setkey(rc4ctx_t *rc4c, uint8 *key, int len)
{
  int i, n, k, l, t;

  rc4c->i = 0;
  rc4c->j = 0;
  
  for(n = 0; n < 256; ++n)
    rc4c->sbox[n] = n;

  for(k = 0, l = 0, i = 0; i < N; ++i)
    for(n = 0; n < 256; ++n)
      {
	t = rc4c->sbox[n];
	k = (key[l] + t + k) & 0xff;
	if(++l == len)
	  l = 0;
	rc4c->sbox[n] = rc4c->sbox[k];
	rc4c->sbox[k] = t;
      }

  /* throw away the first skip keystream bytes */

  for(n = 0; n < skip; ++n)
    rc4_stream(rc4c);
}

void rc4_destruct(rc4ctx_t *rc4c)
{
  memset(rc4c, 0, sizeof(*rc4c));
}

void rc4_crypt(rc4ctx_t *rc4c, const uint8 *src, uint8 *dst, int len)
{
  int i;

  for(i = 0; i < len; ++i)
    dst[i] = src[i] ^ rc4_stream(rc4c);
}

void rc4_crypt_inplace(rc4ctx_t *rc4c, uint8 *data, int len)
{
  int i;

  for(i = 0; i < len; ++i)
    data[i] ^= rc4_stream(rc4c);
}
