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

#include <PowerAuth/Types.h>
#include <cc7/crypto/Crypto.h>

namespace powerAuth {
namespace v3 {

/// Implements old `SecretKey derivedKey = KDF.derive(SecretKey masterKey, long index);`
class LegacyKDF
{
public:
    LegacyKDF(const cc7::crypto::CipherPtr& aes128cbcNoPad);
    
    cc7::ByteArray derive(const cc7::ByteRange& key, uint64_t index) const;
    
private:
    const cc7::crypto::CipherPtr _aes;
};

/// Implements old `SecretKey derivedKey = KDF_INTERNAL.derive(SecretKey masterKey, byte[] index);`
class LegacyKDFInternal
{
public:
    LegacyKDFInternal(const cc7::crypto::MACPtr& hmacSha256);
    
    cc7::ByteArray derive(const cc7::ByteRange& key, const cc7::ByteRange& index) const;
    
private:
    const cc7::crypto::MACPtr _mac;
};

} // namespace v3
} // namespace powerAuth
