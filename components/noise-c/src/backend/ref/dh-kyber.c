/*
Code taken from https://github.com/JoshuaRenckens/PQNoise_Master_Thesis

*/


#include "internal.h"
#include <string.h>

#include "crypto/kyber/api.h"
#include <time.h>

/*
 * Currently missing the SEEC scheme when generating, only to be used in conjunction with the PQNoise patterns
*/

// Create OQS_KEM object initialized with Kyber-512.

typedef struct {
    struct NoiseDHState_s parent;
    uint8_t private_key[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
} NoiseKyberState;

static int noise_kyber_generate_keypair
        (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(st->public_key, st->private_key);
    return NOISE_ERROR_NONE;
}

/*No function given to generate a kyber public key from the private key and I don't feel like writing one at the moment*/
static int noise_kyber_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    /* Doing nothing for now*/
    return NOISE_ERROR_NONE;
}


static int noise_kyber_set_keypair(NoiseDHState *state, const uint8_t *sk, const uint8_t *pk) {
    NoiseKyberState *st = (NoiseKyberState *)state;
    memcpy(st->private_key, sk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    memcpy(st->public_key, pk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    return NOISE_ERROR_NONE;
}


static int noise_kyber_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here */
    return NOISE_ERROR_NONE;
}

static int noise_kyber_copy
        (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    const NoiseKyberState *from_st = (const NoiseKyberState *)from;
    memcpy(st->private_key, from_st->private_key, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    memcpy(st->public_key, from_st->public_key, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_calculate
        (const NoiseDHState *private_key_state,
         const NoiseDHState *public_key_state,
         uint8_t *shared_key)
{
    /*This function should not be called with kyber*/
    return NOISE_ERROR_INVALID_STATE;
}


static int noise_kyber_encapsulate(const NoiseDHState *state, uint8_t *ct, uint8_t *ss) {
    const NoiseKyberState *st = (const NoiseKyberState *)state;
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, st->public_key);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_decapsulate(const NoiseDHState *state, const uint8_t *ct, uint8_t *ss) {
    const NoiseKyberState *st = (const NoiseKyberState *)state;
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, st->private_key);
    return NOISE_ERROR_NONE;
}
NoiseDHState *pqnoise_kyber_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_KYBER;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;
    state->parent.public_key_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    state->parent.shared_key_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES;
    state->parent.cipher_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_kyber_generate_keypair;
    state->parent.set_keypair = noise_kyber_set_keypair;
    state->parent.set_keypair_private = noise_kyber_set_keypair_private;
    state->parent.validate_public_key = noise_kyber_validate_public_key;
    state->parent.copy = noise_kyber_copy;
    state->parent.calculate = noise_kyber_calculate;
    state->parent.encaps = noise_kyber_encapsulate;
    state->parent.decaps = noise_kyber_decapsulate;
    return &(state->parent);
}