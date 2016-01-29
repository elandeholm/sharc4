#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>

#include "sha256.h"
#include "sha256_hmac.h"
#include "rc4.h"
#include "rawtty.h"
#include "readpass.h"

#define MAX_PASS (256)
#define BUFSIZE  (256)

/* Generate entropy for IV by reading from /dev/random
 */

static void generate_IV(uint8 IV[32])
{
  FILE *fp;

  memset(IV, 0, 32);

  fp = fopen("/dev/random", "r");
  if(fp)
    {
      fread(IV, 1, 32, fp);
      fclose(fp);
    }
  else
    {
      fprintf(stderr, "** warning, couldn't read /dev/random - insecure IV generated\n");
    }

#if 0
  {
    int i;
    fprintf(stderr, "made IV:\n");
    
    for(i = 0; i < 32; i += 4)
      {
	fprintf(stderr, "  %02x %02x %02x %02x\n",
		IV[i], IV[i+1], IV[i+2], IV[i+3]);
      }
  }
#endif
}

/* make_key:
 *
 * There are two components in the key.
 * 1) The sha256 hash of the user's pass phrase, and
 * 2) An IV, which is sent in the clear.
 *
 * The purpose of the IV is to allow for multiple encryptions under
 * the same pass phrase. The security of the system does not depend
 * on the IV being secret, but it must never be reused.
 *
 * The derived key is SHA256_HMAC(pass, IV)
 */

static void make_key(uint8 key[32],
		     const uint8 hash[32],
		     const uint8 IV[32])
{
  sha256_hmac_context hmac_ctx;

  /* k = SHA256_HMAC(pass, IV), ie, HMAC of the passphrase using IV as the key
   * Proposed by Dave Wagner in a sci.crypt post:
   * http://groups-beta.google.com/group/sci.crypt/msg/3f12485732f74da2?dmode=source sci.crypt
   */

  sha256_hmac_starts(&hmac_ctx, IV);
  sha256_hmac_update(&hmac_ctx, hash, 32);
  sha256_hmac_finish(&hmac_ctx, key);
  sha256_hmac_destruct(&hmac_ctx);

#if 0
  {
    int i;
    fprintf(stderr, "made key:\n");
    
    for(i = 0; i < 32; i += 4)
      {
	fprintf(stderr, "  %02x %02x %02x %02x\n",
		key[i], key[i+1], key[i+2], key[i+3]);
      }
  }
#endif
}

/* prompt_pass
 * prompt for pass phrase, read from raw tty
 */

static int prompt_pass(uint8 *pass, int plen, int confirm)
{
  int status;

  pass[plen] = '\0';

 retry:
  status = readpass("enter pass phrase: ", pass, MAX_PASS - 1);
  fprintf(stderr, "\n");
  if(status == -1)
    fprintf(stderr, "there was an error\n");
  else
    {
      if(confirm)
	{
	  int status2;
	  uint8 *conf;

	  conf = malloc(plen + 1);
	  conf[plen] = '\0';

	  status2 = readpass("again for confirmation: ",
			     conf, MAX_PASS - 1);
	  fprintf(stderr, "\n");
	  if(status2 == -1)
	    fprintf(stderr, "there was an error\n");
	  else if((status == status2) &&
		  !strcmp((const char *)pass, (const char *)conf))
	    {
	      memset(conf, 0, plen);
	      free(conf);
	    }
	  else
	    {
	      memset(conf, 0, plen);
	      free(conf);
	      fprintf(stderr, "mismatch\n");
	      goto retry;
	    }
	}
    }

  return status;
}

/* rc4 parameters */

static int rc4_N;
static int rc4_skip;

/* mode = 0 => encrypt; mode = 1, decrypt */

static int mode;

static char *infile, *outfile;

static int parse_args(int argc, char **argv)
{
  int c, status;
  int option_index;
  static struct option long_options[] =
  {
    { "encrypt",  0, 0, 0 },
    { "decrypt",  0, 0, 0 },
    { "rc4-N",    1, 0, 0 },
    { "rc4-skip", 1, 0, 0 },
    { 0, 0, 0, 0 }
  };

  mode = 0;
  infile = NULL;
  outfile = NULL;

  rc4_N = 10;
  rc4_skip = 1000;
  
  status = 0;

  while(EOF != (c = getopt_long(argc, argv, "ed",
				long_options, &option_index)))
    {
      switch(c)
	{
	case 0:
	  switch(option_index)
	    {
	    case 0:       /* --encrypt */
	      mode = 0;
	      break;
	    case 1:       /* --decrypt */
	      mode = 1;
	      break;
	    case 2:       /* --rc4-N */
	      if(optarg)
		rc4_N = atoi(optarg);
	      break;
	    case 3:       /* --rc4-skip */
	      if(optarg)
		rc4_skip = atoi(optarg);
	      break;
	    default:
	      fprintf(stderr, "unrecognized long option\n");
	      status = -1;
	      break;
	    }
	  break;
	case 'e':
	  mode = 0;
	  break;
	case 'd':
	  mode = 1;
	  break;
	default:
	  /* fprintf(stderr, "unrecognized option '%c'!\n", c); */
	  status = -1;
	  break;
	}
    }

  if(optind < argc)
    {
      infile = argv[optind];
      ++optind;
    }
  if(optind < argc)
    {
      outfile = argv[optind];
      ++optind;
    }
  if(optind < argc)
    {
      fprintf(stderr, "too many arguments!\n");
      status = -1;
    }

  return status;
}

static int open_files(FILE **in, FILE **out)
{
  if(infile == NULL || !strcmp(infile, "-"))
    *in = stdin;
  else
    {
      *in = fopen(infile, "rb");
      if(*in == NULL)
	{
	  perror("fopen infile");
	  return -1;
	}
    }

  if(outfile == NULL || !strcmp(outfile, "-"))
    *out = stdout;
  else
    {
      *out = fopen(outfile, "wb");
      if(*out == NULL)
	{
	  perror("fopen outfile");
	  return -1;
	}
    }

  return 0;
}

static void close_files(FILE *in, FILE *out)
{
  if(in && in != stdin)
    fclose(in);
  if(out && out != stdout)
    fclose(out);
}

/* Encrypt infile to outfile
 *
 * Encrypted file format:
 *
 * <32 bytes IV>
 * <rc4-encrypted stream>
 * <32 bytes HMAC>
 */

static int sharc4_encrypt(FILE *in, FILE *out)
{
  uint8 pass[MAX_PASS + 1];
  uint8 IV[32];
  uint8 pass_hash[32];
  uint8 rc4_key[32];
  uint8 hmac_key[32];
  uint8 hmac[32];
  uint8 buffer[BUFSIZE];
  rc4ctx_t rc4c;
  sha256_context sha_ctx;
  sha256_hmac_context hmac_ctx;
  int plen;
  int ret;
  int len;
  int i;

  ret = 0;

  plen = prompt_pass(pass, MAX_PASS, 1);

  if(plen == -1)
    ret = -1;
  else
    {
      fprintf(stderr, "encrypting...\n");

      /* generate pass phrase key */

      sha256_starts(&sha_ctx);
      sha256_update(&sha_ctx, pass, plen);
      sha256_finish(&sha_ctx, pass_hash);

      /* generate pseudorandom IV */

      generate_IV(IV);

      /* write IV first */

      fwrite(IV, 1, 32, out);

      /* generate rc4 key */

      make_key(rc4_key, pass_hash, IV);
      rc4_setkey(&rc4c, rc4_key, sizeof(rc4_key));

      /* generate HMAC key */

      for(i = 0; i < sizeof(IV); ++i)
	IV[i] ^= 0xff;

      make_key(hmac_key, pass_hash, IV);
      sha256_hmac_starts(&hmac_ctx, hmac_key);
      
      /* read, update HMAC, encrypt, write until EOF */

      while((len = fread(buffer, 1, BUFSIZE, in)) > 0)
	{
	  sha256_hmac_update(&hmac_ctx, buffer, len);
	  rc4_crypt_inplace(&rc4c, buffer, len);
	  fwrite(buffer, 1, len, out);  
	}

      sha256_hmac_finish(&hmac_ctx, hmac);
      sha256_hmac_destruct(&hmac_ctx);

      /* write HMAC last */

      fwrite(hmac, 1, sizeof(hmac), out);

      /* clr sensitive data */

      rc4_destruct(&rc4c);

      memset(&sha_ctx, 0, sizeof(sha_ctx));

      memset(pass,      0, sizeof(pass));
      memset(pass_hash, 0, sizeof(pass_hash));
      memset(rc4_key,   0, sizeof(rc4_key));
      memset(hmac_key,  0, sizeof(hmac_key));
      memset(hmac,      0, sizeof(hmac));
      memset(buffer,    0, sizeof(buffer));

      plen = 0;
    }

  return ret;
}

/* Decrypt infile to outfile
 *
 * decrypt assumes that infile is of the format
 * described above
 */

static int sharc4_decrypt(FILE *in, FILE *out)
{
  uint8 pass[MAX_PASS + 1];
  uint8 IV[32];
  uint8 pass_hash[32];
  uint8 rc4_key[32];
  uint8 hmac_key[32];
  uint8 buffer[BUFSIZE];
  uint8 buffer2[BUFSIZE];
  uint8 HMAC[32];
  uint8 hmac[32];
  rc4ctx_t rc4c;
  sha256_context sha_ctx;
  sha256_hmac_context hmac_ctx;
  int plen;
  int ret;
  int len;
  int i;

  ret = 0;

  plen = prompt_pass(pass, MAX_PASS, 0);

  if(plen == -1)
    ret = -1;
  else
    {
      /* generate pass phrase key */

      sha256_starts(&sha_ctx);
      sha256_update(&sha_ctx, pass, plen);
      sha256_finish(&sha_ctx, pass_hash);

      /* read IV */

      len = fread(IV, 1, 32, in);
      if(len < 32)
	{
	  fprintf(stderr, "** decrypted file is too short!\n");
	  ret = -1;
	}
      else
	{
	  fprintf(stderr, "decrypting...\n");

	  /* generate rc4 key */

	  make_key(rc4_key, pass_hash, IV);
	  rc4_setkey(&rc4c, rc4_key, sizeof(rc4_key));

	  /* generate HMAC key */

	  for(i = 0; i < sizeof(IV); ++i)
	    IV[i] ^= 0xff;

	  make_key(hmac_key, pass_hash, IV);
	  sha256_hmac_starts(&hmac_ctx, hmac_key);

	  /* the HMAC buffer always contains the last 32 bytes
	   * from the infile
	   */
	  
	  len = fread(HMAC, 1, 32, in);

	  if(len < 32)
	    {
	      fprintf(stderr, "** decrypted file is too short!\n");
	      ret = -1;
	    }
	  else do
	    {
	      /* read, decrypt, update HMAC, write until EOF */

	      len = fread(buffer, 1, BUFSIZE, in);

	      memcpy(buffer2, HMAC, 32);
	      
	      if(len == BUFSIZE)
		{
		  memcpy(&buffer2[32], buffer, BUFSIZE - 32);
		  memcpy(HMAC, &buffer[BUFSIZE - 32], 32);
		}
	      else
		{
		  /* input file is exhausted. the last 32 bytes
		   * contains the HMAC, so they need special treatment
		   * since they are not to be decrypted
		   */

		  if(len > 32)
		    {
		      memcpy(&buffer2[32], buffer, len - 32);
		      memcpy(HMAC, &buffer[len - 32], 32);
		    }
		  else
		    {
		      if(len)
			{
			  for(i = 0; i + len < 32; ++i)
			    HMAC[i] = HMAC[i + len];
			  memcpy(&HMAC[i], buffer, len);
			}
		    }
		}
	      
	      /* buffer2 contains the first len bytes of the
	       * concatenation of the previous last 32 bytes
	       * and the first len - 32 bytes of the read buffer
	       */

	      if(len > 0)
		{
		  rc4_crypt_inplace(&rc4c, buffer2, len);
		  sha256_hmac_update(&hmac_ctx, buffer2, len);
		  fwrite(buffer2, 1, len, out);	  
		}
	    } while(len > 0);
	  
	  sha256_hmac_finish(&hmac_ctx, hmac);
	  sha256_hmac_destruct(&hmac_ctx);

	  /* check if computed HMAC and read HMAC agree */

	  if(memcmp(hmac, HMAC, 32))
	    {
	      fprintf(stderr, "** file does not decrypt!\n");
	      ret = -1;
	    }
	}

      /* clr sensitive data */
      
      rc4_destruct(&rc4c);
      
      memset(&sha_ctx, 0, sizeof(sha_ctx));

      memset(pass,      0, sizeof(pass));
      memset(pass_hash, 0, sizeof(pass_hash));
      memset(rc4_key,   0, sizeof(rc4_key));
      memset(hmac_key,  0, sizeof(hmac_key));
      memset(buffer,    0, sizeof(buffer));
      memset(buffer2,   0, sizeof(buffer2));
      memset(HMAC,      0, sizeof(HMAC));

      plen = 0;
    }
  
  return ret;
}

int main(int argc, char **argv)
{
  int status, ret;
  FILE *in, *out;

  ret = 0;

  status = parse_args(argc, argv);
  if(status == -1)
    {
      fprintf(stderr, "usage: sharc4 --[encrypt|decrypt] in out\n");
      ret = -1;
      goto bailout;
    }

  status = open_files(&in, &out);
  if(status == -1)
    {
      ret = -1;
    }
  else
    {
      rc4_parameters(rc4_N, rc4_skip);

      if(mode == 0)
	ret = sharc4_encrypt(in, out);
      else
	ret = sharc4_decrypt(in, out);
    }

  close_files(in, out);

 bailout:
  return ret;
}
