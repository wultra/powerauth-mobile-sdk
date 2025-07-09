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
#include <PowerAuth/Encryptor.h>
#include "../v4/HybridKeyPair.h"

namespace powerAuth {

class RegistrationData
{
public:
    struct V4
    {
        std::string activationId;
        cc7::ByteArray authCodeCounterData;
        cc7::ByteArray ecdsaServerPublicKey;
        cc7::ByteArray mldsaServerPublicKey;
        
        cc7::crypto::KeyPairPtr deviceKeyPair;
        cc7::crypto::PublicKeyPtr serverPublicKey;
        
        IClientEncryptorPtr requestEncryptor;
        ISharedSecretPtr sharedSecretAlgorithm;
        SharedSecretContextPtr sharedSecretContext;
        cc7::ByteArray calculatedSharedSecret;
    };
    
    struct V3
    {
        cc7::crypto::KeyPairPtr deviceKeyPair;
        cc7::crypto::PublicKeyPtr serverPublicKey;
    };
    
    V4& v4();
    const V4& v4() const;
    
    V3& v3();
    const V3& v3() const;
    
    static std::unique_ptr<RegistrationData> create(ProtocolVersion version);
    
private:
    
    RegistrationData(ProtocolVersion version);
    
    /// Data version
    const ProtocolVersion _version;
    /// Pointer to V3 data
    const std::unique_ptr<V3> _v3;
    /// Pointer to V4 data
    const std::unique_ptr<V4> _v4;
};

typedef std::unique_ptr<RegistrationData> RegistrationDataPtr;

} // namespace powerAuth
