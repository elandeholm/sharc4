#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include "sha256.h"

static char *sha256_tv[] =
{
  "abc",
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  NULL
};

static uint8 sha256_facit[3][32] =
{
  { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  },
  { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
  },
  {
    0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
    0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
    0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
    0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
  }
};

int sha256_verify(void)
{
  uint8 hash[32];
  sha256_context ctx;
  int i;

  for(i = 0; sha256_tv[i]; ++i)
    {
      sha256_starts(&ctx);
      sha256_update(&ctx, (uint8 *)sha256_tv[i], strlen(sha256_tv[i]));
      sha256_finish(&ctx, hash);

      if(memcmp(sha256_facit[i], hash, sizeof(hash)))
	{
	  fprintf(stderr, "sha-256 test %d failed\n", i + 1);
	  return 0;
	}
    }

  sha256_starts(&ctx);

  for(i = 0; i < 1000000; i += 16)
    sha256_update(&ctx, (uint8 *)"aaaaaaaaaaaaaaaa", 16);
  
  sha256_finish(&ctx, hash);
  
  if(memcmp(sha256_facit[2], hash, sizeof(hash)))
    {
      fprintf(stderr, "sha-256 test 3 failed\n");
      return 0;
    }

  return 1;
}

static void start_timer(struct timeval *t0)
{
  gettimeofday(t0, NULL);
}

static void stop_print_timer(struct timeval *t0)
{
  struct timeval t;
  long long usecs;

  gettimeofday(&t, NULL);
  usecs = t.tv_usec - t0->tv_usec;
  usecs += 1000000 * (t.tv_sec - t0->tv_sec);

  fprintf(stderr, "%lld usecs\n", usecs);
}

void sha256_benchmark(void)
{
  int i, j, size, ntimes, N;
  sha256_context ctx;
  struct timeval t0;
  int datasize = 1048576;
  uint8 *data;
  uint8 hash[32];

  data = malloc(datasize);
  if(!data)
    {
      fprintf(stderr, "out of memory\n");
      return;
    }

  N = 1048576;

  for(i = 0; i < datasize; ++i)
    data[i] = 0xff;

  for(i = 1; i <= datasize; i <<= 1)
    {
      size = i;
      ntimes = N / size;

      fprintf(stderr, "%7d x %7d ", size, ntimes);
      start_timer(&t0);
      sha256_starts(&ctx);
      for(j = 0; j < ntimes; ++j)
	sha256_update(&ctx, data, size);
      sha256_finish(&ctx, hash);  
      stop_print_timer(&t0);
    }
}

static void sha256_file(sha256_context *ctx, FILE *fp)
{
  int bufsize = 512, status;
  uint8 *buffer;

  buffer = malloc(bufsize);
  while((status = fread(buffer, 1, bufsize, fp)) > 0)
    sha256_update(ctx, buffer, status);
}

static void print_hash(uint8 hash[32], const char *arg)
{
  int i;

  for(i = 0; i < 32; ++i)
    {
      printf("%02x", hash[i]);
      if((i & 3) == 3)
	printf(" ");
    }

  printf("  %s\n", arg);
}

static void parse_args(int argc, char **argv, int *benchmark, int *verify)
{
  int c;

  while(EOF != (c = getopt(argc, argv, "bv")))
    {
      switch(c)
	{
	case 'b':
	  *benchmark = 1;
	  break;
	case 'v':
	  *verify = 1;
	  break;
	}
    }
}

int main(int argc, char **argv)
{
  int i, benchmark, verify;
  sha256_context ctx;
  uint8 hash[32];
  FILE *fp;

  benchmark = 0;
  verify = 0;

  parse_args(argc, argv, &benchmark, &verify);

  if(verify)
    {
      fprintf(stderr, "** verifying sha-256 engine **\n");
      if(!sha256_verify())
	exit(1);
      fprintf(stderr, "all tests OK\n");
    }

  if(benchmark)
    {
      fprintf(stderr, "** benchmarking sha-256 engine **\n");
      sha256_benchmark();
    }

  for(i = optind; i < argc; ++i)
    {
      fp = strcmp(argv[i], "-") ? fopen(argv[i], "rb") : stdin;
      if(fp == NULL)
	{
	  fprintf(stderr, "file not found: %s\n", argv[i]);
	  continue;
	}
      else
	{
	  sha256_starts(&ctx);
	  sha256_file(&ctx, fp);
	  sha256_finish(&ctx, hash);
	  print_hash(hash, argv[i]);
	  if(fp != stdin)
	    fclose(fp);
	}
    }

  if((optind == argc) && !verify && !benchmark)
    {
      sha256_starts(&ctx);
      sha256_file(&ctx, stdin);
      sha256_finish(&ctx, hash);
      print_hash(hash, "-");
    }

  return 0;
}
