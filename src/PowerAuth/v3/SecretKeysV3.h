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

#include <PowerAuth/KeyProvider.h>
#include "../common/SecretKeysPool.h"
#include "../Context.h"

namespace powerAuth {
namespace v3 {

class KeyProviderV3;

class SecretKeysV3 : public ISecretKeys
{
public:
    enum KeyId
    {
        // Input keys
        KEY_SHARED_SECRET,
      
        KEK_AUTHENTICATION_KNOWLEDGE,
        KEK_AUTHENTICATION_BIOMETRY,    // 16 bytes
        
        CKEY_AUTHENTICATION_POSSESSION, // LegacyUKE (16)
        CKEY_AUTHENTICATION_KNOWLEDGE,  // LegacyUKE (16)
        CKEY_AUTHENTICATION_BIOMETRY,   // LegacyUKE (16)
        CKEY_TRANSPORT,                 // LegacyUKE (16)
        
        CKEY_DEVICE_PRIVATE,            // AEAD variable size
        
        IN_DEVICE_SPECIFIC_DATA,        // any data
        IN_PASSWORD,                    // any data
        IN_PASSWORD_SALT,               // 32 bytes
        IN_ACTIVATION_ID,               // activation-ID (UUID)
        IN_APP_SECRET,                  // app secret    (16B)
        
        // Keys below this marker are input keys
        KID_INPUT,

        KEY_AUTHENTICATION_POSSESSION = KID_INPUT,
        KEY_AUTHENTICATION_KNOWLEDGE,
        KEY_AUTHENTICATION_BIOMETRY,
        
        KEY_ENCRYPTION_VAULT,
        KEY_TRANSPORT,
        
        
        // Keys below this marker can be set at input, or derived if
        // appropriate source key is available
        KID_INPUT_OUTPUT,

        KEY_TRANSPORT_IV = KID_INPUT_OUTPUT,
        KEY_TRANSPORT_CTR,
        
        // Number of keys
        KID_COUNT,
        
        // ID for no-source key
        KID_NONE = 1000
    };
};

} // namespace v3
} // namespace powerAuth
