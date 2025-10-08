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

#include <PowerAuth/Encryptor.h>
#include "../v4/HybridKeyPair.h"

namespace powerAuth {

class Context;

class UpgradeData
{
public:
    struct V4
    {
        cc7::crypto::KeyPairPtr deviceKeyPair;
        cc7::crypto::PublicKeyPtr serverPublicKey;
        
        ISharedSecretPtr sharedSecretAlgorithm;
        SharedSecretContextPtr sharedSecretContext;
        cc7::ByteArray calculatedSharedSecret;
        
        cc7::ByteArray authCodeCounterData;
        
        std::shared_ptr<Context> context;
    };
    
    V4& v4();
    const V4& v4() const;
    
    static std::unique_ptr<UpgradeData> create();

private:
    UpgradeData();
    
    const std::unique_ptr<V4> _v4;
};

typedef std::unique_ptr<UpgradeData> UpgradeDataPtr;

} // namespace powerAuth
