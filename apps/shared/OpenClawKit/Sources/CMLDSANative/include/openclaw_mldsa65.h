/*
 * Copyright (c) 2026 OpenClaw contributors
 * SPDX-License-Identifier: MIT
 */

#ifndef OPENCLAW_MLDSA65_H
#define OPENCLAW_MLDSA65_H

#include <stddef.h>
#include <stdint.h>

#define OPENCLAW_MLDSA65_SEED_BYTES 32
#define OPENCLAW_MLDSA65_RANDOM_BYTES 32
#define OPENCLAW_MLDSA65_PUBLIC_KEY_BYTES 1952
#define OPENCLAW_MLDSA65_SIGNATURE_BYTES 3309

#ifdef __cplusplus
extern "C" {
#endif

int openclaw_mldsa65_public_from_seed(
    const uint8_t *seed,
    size_t seed_length,
    uint8_t *public_key,
    size_t public_key_length);

int openclaw_mldsa65_sign(
    const uint8_t *seed,
    size_t seed_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *randomness,
    size_t randomness_length,
    uint8_t *signature,
    size_t signature_length);

int openclaw_mldsa65_verify(
    const uint8_t *public_key,
    size_t public_key_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *signature,
    size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
