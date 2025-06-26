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

#include <cc7/crypto/Crypto.h>

namespace powerAuth {
namespace v4 {

class PowerAuthKDF : public cc7::crypto::KeyDerivation
{
public:
    cc7::ByteArray derive(const cc7::ByteRange & key,
                          const std::string & label,
                          const cc7::ByteRange & diversifier = cc7::ByteRange(),
                          size_t out_size = 32) const;
    
    // KeyDerivation
    cc7::ByteArray deriveKeyBytes(const cc7::ByteRange &key_material, const cc7::crypto::ParameterList &parameters) const override;
    
    // Algorithm
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const cc7::crypto::Parameter & value) override;
    cc7::crypto::Parameter getParameter(int param_id) const  override;
    
    PowerAuthKDF(const cc7::crypto::MACPtr & kmac);
    
private:
    static const std::string ALG_NAME;
    cc7::crypto::MACPtr _kmac;
};

class PowerAuthPassKDF : public cc7::crypto::KeyDerivation
{
public:
    cc7::ByteArray derive(const cc7::ByteRange & key,
                          const cc7::ByteRange & salt,
                          size_t out_size = 32) const;
    
    // KeyDerivation
    cc7::ByteArray deriveKeyBytes(const cc7::ByteRange &key_material, const cc7::crypto::ParameterList &parameters) const override;
    
    // Algorithm
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const cc7::crypto::Parameter & value) override;
    cc7::crypto::Parameter getParameter(int param_id) const  override;
    
    PowerAuthPassKDF(const cc7::crypto::MACPtr & kmac);
    
private:
    static const std::string ALG_NAME;
    cc7::crypto::MACPtr _kmac;
};

typedef std::shared_ptr<PowerAuthKDF> PowerAuthKdfPtr;
typedef std::shared_ptr<PowerAuthPassKDF> PowerAuthPassKdfPtr;

} // namespace v4
} // namespace powerAuth
