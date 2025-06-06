/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "noise/defines.h"
#if NOISE_USE_LIBSODIUM

#include "protocol/internal.h"
#include <sodium.h>
#include <string.h>
#include "esp_cpu.h"
#include <noise_log.h>

typedef struct
{
    struct NoiseDHState_s parent;
    uint8_t private_key[32];
    uint8_t public_key[32];

} NoiseCurve25519State;

static int noise_curve25519_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    noise_rand_bytes(st->private_key, 32);
    st->private_key[0] &= 0xF8;
    st->private_key[31] = (st->private_key[31] & 0x7F) | 0x40;
    bench_start_ed25519("ED25519_scalar_mult_base"); 
    crypto_scalarmult_curve25519_base(st->public_key, st->private_key);
    bench_end_ed25519("ED25519_scalar_mult_base");
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Check that the public key actually corresponds to the private key */
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    uint8_t temp[32];
    int equal;
    bench_start_ed25519("ED25519_scalar_mult_base"); 
    crypto_scalarmult_curve25519_base(temp, private_key);
    bench_end_ed25519("ED25519_scalar_mult_base");
    equal = noise_is_equal(temp, public_key, 32);
    memcpy(st->private_key, private_key, 32);
    memcpy(st->public_key, public_key, 32);
    return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_curve25519_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    memcpy(st->private_key, private_key, 32);
    bench_start_ed25519("ED25519_scalar_mult_base"); 
    crypto_scalarmult_curve25519_base(st->public_key, st->private_key);
    bench_end_ed25519("ED25519_scalar_mult_base");
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    const NoiseCurve25519State *from_st = (const NoiseCurve25519State *)from;
    memcpy(st->private_key, from_st->private_key, 32);
    memcpy(st->public_key, from_st->public_key, 32);
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    bench_start_ed25519("ED25519_scalar_mult"); 
    int ret = crypto_scalarmult_curve25519(
        shared_key, private_key_state->private_key,
        public_key_state->public_key
    );
    bench_end_ed25519("ED25519_scalar_mult");
    if (ret != 0) {
        // return value is always 0; return value only used
        // to ensure constant timing
        return NOISE_ERROR_INVALID_PARAM;
    }
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void)
{
    NoiseCurve25519State *state = noise_new(NoiseCurve25519State);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_CURVE25519;
    state->parent.nulls_allowed = 1;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_curve25519_generate_keypair;
    state->parent.set_keypair = noise_curve25519_set_keypair;
    state->parent.set_keypair_private = noise_curve25519_set_keypair_private;
    state->parent.validate_public_key = noise_curve25519_validate_public_key;
    state->parent.copy = noise_curve25519_copy;
    state->parent.calculate = noise_curve25519_calculate;
    return &(state->parent);
}

#endif // NOISE_USE_LIBSODIUM
