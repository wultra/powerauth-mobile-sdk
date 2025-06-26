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

#include "HybridKeyPair.h"

namespace powerAuth {
namespace v4 {

class HybridSignature : public cc7::crypto::Signature
{
public:
    HybridSignature(const cc7::crypto::SignaturePtr & alg1, const cc7::crypto::SignaturePtr & alg2);
    
    // Algorithm interface
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const cc7::crypto::Parameter & value) override;
    cc7::crypto::Parameter getParameter(int param_id) const override;

    // Signature interface
    cc7::ByteArray sign(const cc7::crypto::PrivateKey &private_key, const cc7::ByteRange &data, const cc7::crypto::ParameterList &parameters = {}) const override;
    bool verify(const cc7::crypto::PublicKey &public_key, const cc7::ByteRange &signature, const cc7::ByteRange &data, const cc7::crypto::ParameterList &parameters = {}) const override;
};

} // namespace v4
} // namespace powerAuth
