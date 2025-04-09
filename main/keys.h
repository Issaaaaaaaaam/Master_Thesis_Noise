#pragma once
#include <stdint.h>

// X25519 keys
extern const uint8_t local_private[32];
extern const uint8_t local_public[32];
extern const uint8_t remote_public[32];

// Kyber keys
extern const uint8_t local_private_pq[1632];
extern const uint8_t local_public_pq[800];
extern const uint8_t remote_public_pq[800];