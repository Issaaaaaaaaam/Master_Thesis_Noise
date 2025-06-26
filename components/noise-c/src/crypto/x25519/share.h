#ifndef _SHARE_H
#define _SHARE_H

#define MPISE_XLEN 32

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if   ( MPISE_XLEN == 32 )
typedef uint32_t Word;
#define WBYTES 4
#define WBITS 32
#define WPOW2 5
#define FORMATSTR "%08lX"
#elif ( MPISE_XLEN == 64 )
typedef uint64_t Word;
#define WBYTES 8
#define WBITS 64
#define WPOW2 6
#define FORMATSTR "%016llX"
#endif

// the constant of Curve25519
#define CONSTA 486662
// number of words of a field-element
#define NWORDS (256/WBITS)

// auxiliary functions
void rand_bytes(uint8_t *x, int n);
void mpi_print(const char *c, const Word *a, int len);

#endif
