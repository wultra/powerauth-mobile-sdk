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

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

class PowerAuthKDF;

class PowerAuthAEAD : public cc7::crypto::AEAD
{
public:
    // AEAD
    cc7::ByteArray seal(const cc7::ByteRange &key, const cc7::ByteRange &nonce, const cc7::ByteRange &associated_data, const cc7::ByteRange &plaintext, const cc7::crypto::ParameterList &params) const override;
    cc7::ByteArray open(const cc7::ByteRange &key, const cc7::ByteRange &associated_data, const cc7::ByteRange &ciphertext, const cc7::crypto::ParameterList &params) const override;

    // Algorithm
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const cc7::crypto::Parameter & value) override;
    cc7::crypto::Parameter getParameter(int param_id) const  override;
    
    PowerAuthAEAD(const std::shared_ptr<PowerAuthKDF> & kdf, const cc7::crypto::CipherPtr & cipher, const cc7::crypto::MACPtr & mac);
        
private:
    
    static const std::string ALG_NAME;
    
    static const size_t NONCE_SIZE;
    static const size_t TAG_SIZE;
    static const std::string MAC_CUSTOM;
    static const std::string KEY_ENC_LABEL;
    static const std::string KEY_MAC_LABEL;
    static const cc7::crypto::ParameterList MAC_PARAMS;

    std::shared_ptr<PowerAuthKDF> _kdf;
    cc7::crypto::CipherPtr  _cipher;
    cc7::crypto::MACPtr     _mac;
};

} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
