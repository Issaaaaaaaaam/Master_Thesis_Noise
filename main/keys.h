#pragma once
#include <stdint.h>

// X25519 keys
extern const uint8_t local_private[32];
extern const uint8_t local_public[32];
extern const uint8_t remote_public[32];

// Kyber keys
extern const uint8_t local_private_pq_512[1632];
extern const uint8_t local_public_pq_512[800];
extern const uint8_t remote_public_pq_512[800];


// Kyber keys
extern const uint8_t local_private_pq_768[2400];
extern const uint8_t local_public_pq_768[1184];
extern const uint8_t remote_public_pq_768[1184];