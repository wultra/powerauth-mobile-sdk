/*
 * Copyright 2021 Wultra s.r.o.
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

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
    // PA version string
    extern const std::string PA_VERSION_V2;
    extern const std::string PA_VERSION_V3;
    
    // PA HTTP Auth header. Contains X-PowerAuth-Authorization string
    extern const std::string PA_AUTH_HEADER_NAME;
    
    // Other header strings
    extern const std::string PA_AUTH_FRAGMENT_BEGIN_VERSION;
    extern const std::string PA_AUTH_FRAGMENT_ACTIVATION_ID;
    extern const std::string PA_AUTH_FRAGMENT_APPLICATION_KEY;
    extern const std::string PA_AUTH_FRAGMENT_NONCE;
    extern const std::string PA_AUTH_FRAGMENT_SIGNATURE_TYPE;
    extern const std::string PA_AUTH_FRAGMENT_SIGNATURE;
    extern const std::string PA_AUTH_FRAGMENT_END;
    extern const size_t      PA_AUTH_FRAGMENTS_LENGTH;
    
    // App secret & key for offline signatures
    extern const std::string PA_OFFLINE_APP_SECRET;
    
    // Empty IV (16 bytes filled with 0)
    extern const cc7::ByteArray ZERO_IV;
    
    // Various constant strings
    extern const std::string AMP;       // "&"
    extern const std::string DASH;      // "-"
    
    // How many iterations are used for password key derivation.
    const size_t PBKDF2_PASS_ITERATIONS = 10000;
    
    // How many iterations are used for OTP key expanding.
    const size_t PBKDF2_OTP_EXPAND_ITERATIONS = 10000;
    
    // Length of generated salt
    const size_t PBKDF2_SALT_SIZE = 16;
    
    // Length of all keys related to signature
    const size_t SIGNATURE_KEY_SIZE = 16;
    
    // Length of vault key.
    const size_t VAULT_KEY_SIZE = 16;
    
    // Minimal password length
    const size_t MINIMAL_PASSWORD_LENGTH = 4;
    
    // Length of key produced by ECDH
    const size_t SHARED_SECRET_KEY_SIZE = 32;
    
    // Length of decimalized signature, calculated from device public key
    const size_t ACTIVATION_FINGERPRINT_SIZE = 8;
    
    // Length of status blob
    const size_t STATUS_BLOB_SIZE = 32;
    
    // Length of status blob challenge data.
    const size_t STATUS_BLOB_CHALLENGE_SIZE = 16;
    
    // Length of expected status blob nonce data.
    const size_t STATUS_BLOB_NONCE_SIZE = STATUS_BLOB_CHALLENGE_SIZE;
    
    // Length of APPLICATION_KEY, APPLICATION_SECRET
    const size_t APPLICATION_KEY_SIZE = 16;
    const size_t APPLICATION_SECRET_SIZE = 16;
    
    // Default value for look ahead window
    const size_t LOOK_AHEAD_DEFAULT = 20;
    // Maximum supported look ahead.
    const size_t LOOK_AHEAD_MAX = 64;

    // 16 bytes encoded in Base64 equals to 24 characters long string.
    const size_t OFFLINE_SIGNATURE_NONCE_LENGTH = 24;
    // Minimum decimal signature component length.
    const size_t DECIMAL_SIGNATURE_MIN_LENGTH = 4;
    // Maximum decimal signature component length.
    const size_t DECIMAL_SIGNATURE_MAX_LENGTH = 8;
    
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
