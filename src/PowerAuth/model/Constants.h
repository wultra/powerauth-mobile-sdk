/*
 * Copyright 2025 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cc7/ByteArray.h>

namespace powerAuth {

// MARK: - Common

namespace common {

/// Encryption header name
extern const std::string PA_ENCRYPTION_HEADER_NAME;

/// Authentication header name
extern const std::string PA_AUTHENTICATION_HEADER_NAME;

/// Token header name
extern const std::string PA_TOKEN_HEADER_NAME;

/// App secret for offline authentication code.
extern const std::string PA_OFFLINE_APP_SECRET;

/// Empty IV (16 bytes filled with 0)
extern const cc7::ByteArray ZERO16_IV;

/// String containing ampersand "&".
extern const std::string AMP;
/// String containing dash "-".
extern const std::string DASH;

/// Size of APPLICATION_KEY
const size_t APPLICATION_KEY_SIZE = 16;
/// Size of  APPLICATION_SECRET.
const size_t APPLICATION_SECRET_SIZE = 16;

/// Minimal password length
const size_t MINIMAL_PASSWORD_LENGTH = 4;

/// 16 bytes encoded in Base64 equals to 24 characters long string.
const size_t OFFLINE_AUTH_CODE_NONCE_LENGTH = 24;

/// Minimum length for human readable authentication code.
const size_t DECIMAL_AUTH_CODE_MIN_LENGTH = 4;
/// Maximum length for human readable authentication code.
const size_t DECIMAL_AUTH_CODE_MAX_LENGTH = 8;

/// Length of fingerprint calculated from activation public keys.
const size_t ACTIVATION_FINGERPRINT_LENGTH = 8;

} // namespace common

// MARK: - Protocol V4

namespace v4 {

/// PA version string for protocol V4
extern const std::string PA_VERSION_STRING;

/// Length of generated salt
const size_t PASSKDF_SALT_SIZE = 32;

/// Length of all factor keys
const size_t FACTOR_KEY_SIZE = 32;

/// Lenght of factor key encrypted with UKE
const size_t UKE_PROTECTED_KEY_SIZE = 16 + 32;

/// Lenght of factor (or similar) key encrypted with AEAD
const size_t AEAD_PROTECTED_KEY_SIZE = 12 + 32 + 32;

/// Length of vault key.
const size_t VAULT_KEY_SIZE = 32;

/// Size of HASH counter used in authentication code calculation.
const size_t HASH_COUNTER_SIZE = 32;

/// Length of decimalized signature, calculated from device & server public keys
const size_t ACTIVATION_FINGERPRINT_SIZE = 8;

/// Default value for look ahead window
const size_t LOOK_AHEAD_DEFAULT = 20;
/// Maximum supported look ahead.
const size_t LOOK_AHEAD_MAX = 64;

/// Length of nonce in bytes, in online authentication header.
const size_t ONLINE_AUTH_CODE_NONCE_LENGTH = 16;

/// Length of authentication code component
const size_t AUTH_CODE_COMPONENT_LENGTH = 32;

/// Length of activation status blob
const size_t STATUS_BLOB_SIZE = 48;

/// Length of MAC calculated from activation status blob
const size_t STATUS_MAC_SIZE = 32;

/// Size of token's secret.
const size_t TOKEN_SECRET_SIZE = 32;

/// Size of calculated token digest.
const size_t TOKEN_DIGEST_SIZE = 32;

} // namespace v4


// MARK: - Protocol V3

namespace v3 {

/// PA version string for protocol V3
extern const std::string PA_VERSION_STRING;

/// How many iterations are used for password key derivation.
const size_t PBKDF2_PASS_ITERATIONS = 10000;

/// How many iterations are used for OTP key expanding.
const size_t PBKDF2_OTP_EXPAND_ITERATIONS = 10000;

/// Length of generated salt
const size_t PBKDF2_SALT_SIZE = 16;

/// Length of all keys related to signature
const size_t FACTOR_KEY_SIZE = 16;

/// Length of vault key.
const size_t VAULT_KEY_SIZE = 16;


const size_t HASH_COUNTER_SIZE = 16;

/// Length of key produced by ECDH
const size_t SHARED_SECRET_KEY_SIZE = 32;

/// Length of decimalized signature, calculated from device & server public keys
const size_t ACTIVATION_FINGERPRINT_SIZE = 8;

/// Length of status blob
const size_t STATUS_BLOB_SIZE = 32;

/// Length of status blob challenge data.
const size_t STATUS_BLOB_CHALLENGE_SIZE = 16;

/// Length of expected status blob nonce data.
const size_t STATUS_BLOB_NONCE_SIZE = STATUS_BLOB_CHALLENGE_SIZE;

/// Default value for look ahead window
const size_t LOOK_AHEAD_DEFAULT = 20;
/// Maximum supported look ahead.
const size_t LOOK_AHEAD_MAX = 64;

/// Size of token's secret.
const size_t TOKEN_SECRET_SIZE = 16;

/// Length of nonce in bytes, in online authentication header.
const size_t ONLINE_AUTH_CODE_NONCE_LENGTH = 16;
/// Length of authentication code component
const size_t AUTH_CODE_COMPONENT_LENGTH = 16;

} // namespace v3

} // namespace powerAuth
