CC=gcc
CC-FLAGS=-Wall -g -march=native
CC-OPTFLAGS=-O3 -march=native

RM=rm
RM-FLAGS=-f

TAR=tar
TAR-FLAGS=cf -

BZ=bzip2
BZ-OPTS=-9c

sha256sum.o:	sha256sum.c sha256.h
	$(CC) $(CC-FLAGS) -o sha256sum.o -c sha256sum.c

sha256sum:	sha256sum.o sha256.o
	$(CC) $(CC-FLAGS) -o sha256sum sha256sum.o sha256.o

sha256.o: sha256.c sha256.h
	$(CC) $(CC-OPTFLAGS) -o sha256.o -c sha256.c

sha256_hmac.o: sha256_hmac.c sha256_hmac.h sha256.h
	$(CC) $(CC-OPTFLAGS) -o sha256_hmac.o -c sha256_hmac.c

rc4.o:	rc4.c rc4.h
	$(CC) $(CC-OPTFLAGS) -o rc4.o -c rc4.c

rawtty.o:	rawtty.c
	$(CC) $(CC-FLAGS) -o rawtty.o -c rawtty.c

readpass.o:	readpass.c readpass.h rawtty.h
	$(CC) $(CC-FLAGS) -o readpass.o -c readpass.c

sharc4.o:	sharc4.c sha256.h sha256_hmac.h rc4.h rawtty.h readpass.h
	$(CC) $(CC-FLAGS) -o sharc4.o -c sharc4.c

sharc4:	sharc4.o sha256.o sha256_hmac.o rc4.o rawtty.o readpass.o
	$(CC) $(CC-FLAGS) -o sharc4 sharc4.o sha256.o sha256_hmac.o rc4.o rawtty.o readpass.o

snapshot:	*.c *.h Makefile
	$(TAR) $(TAR-FLAGS) *.c *.h Makefile RCS | $(BZ) $(BZ-OPTS) > sharc4.tar.bz2

clean:
	$(RM) $(RM-FLAGS) sha256.o sha256_hmac.o rc4.o rawtty.o readpass.o sha256sum.o sha256sum.exe sha256sum sharc4.o sharc4.exe sharc4
