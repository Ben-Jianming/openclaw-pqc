/*
 * Copyright (c) 2026 OpenClaw contributors
 * SPDX-License-Identifier: MIT
 */

#include "openclaw_mldsa65.h"
#include "mldsa_native.h"

#include <stddef.h>
#include <stdint.h>

static void openclaw_secure_zero(void *pointer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  while (length-- > 0) {
    *bytes++ = 0;
  }
}

static int openclaw_valid_buffer(const uint8_t *buffer, size_t length) {
  return buffer != NULL || length == 0;
}

int openclaw_mldsa65_public_from_seed(
    const uint8_t *seed,
    size_t seed_length,
    uint8_t *public_key,
    size_t public_key_length) {
  uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
  int result;

  if (seed == NULL || seed_length != OPENCLAW_MLDSA65_SEED_BYTES ||
      public_key == NULL ||
      public_key_length != OPENCLAW_MLDSA65_PUBLIC_KEY_BYTES) {
    return MLD_ERR_INVALID_ARG;
  }

  result = openclaw_mldsa_keypair_internal(public_key, secret_key, seed);
  openclaw_secure_zero(secret_key, sizeof(secret_key));
  return result;
}

int openclaw_mldsa65_sign(
    const uint8_t *seed,
    size_t seed_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *randomness,
    size_t randomness_length,
    uint8_t *signature,
    size_t signature_length) {
  uint8_t public_key[MLDSA65_PUBLICKEYBYTES];
  uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
  static const uint8_t empty_context_prefix[2] = {0, 0};
  int result;

  if (seed == NULL || seed_length != OPENCLAW_MLDSA65_SEED_BYTES ||
      !openclaw_valid_buffer(message, message_length) ||
      randomness == NULL ||
      randomness_length != OPENCLAW_MLDSA65_RANDOM_BYTES ||
      signature == NULL ||
      signature_length != OPENCLAW_MLDSA65_SIGNATURE_BYTES) {
    return MLD_ERR_INVALID_ARG;
  }

  result = openclaw_mldsa_keypair_internal(public_key, secret_key, seed);
  if (result == 0) {
    result = openclaw_mldsa_signature_internal(
        signature,
        message,
        message_length,
        empty_context_prefix,
        sizeof(empty_context_prefix),
        randomness,
        secret_key,
        0);
  }
  openclaw_secure_zero(secret_key, sizeof(secret_key));
  openclaw_secure_zero(public_key, sizeof(public_key));
  return result;
}

int openclaw_mldsa65_verify(
    const uint8_t *public_key,
    size_t public_key_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *signature,
    size_t signature_length) {
  static const uint8_t empty_context_prefix[2] = {0, 0};

  if (public_key == NULL ||
      public_key_length != OPENCLAW_MLDSA65_PUBLIC_KEY_BYTES ||
      !openclaw_valid_buffer(message, message_length) ||
      signature == NULL ||
      signature_length != OPENCLAW_MLDSA65_SIGNATURE_BYTES) {
    return MLD_ERR_INVALID_ARG;
  }

  return openclaw_mldsa_verify_internal(
      signature,
      message,
      message_length,
      empty_context_prefix,
      sizeof(empty_context_prefix),
      public_key,
      0);
}
