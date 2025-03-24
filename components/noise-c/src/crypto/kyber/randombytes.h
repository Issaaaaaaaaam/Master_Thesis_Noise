#ifndef PQCLEAN_MLKEM512_CLEAN_RANDOMBYTES_H
#define PQCLEAN_MLKEM512_CLEAN_RANDOMBYTES_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

static inline void kyber_randombytes(uint8_t *output, size_t n) {
    randombytes_buf(output, n);  // libsodium’s secure RNG
}

#endif // PQCLEAN_MLKEM512_CLEAN_RANDOMBYTES_H
