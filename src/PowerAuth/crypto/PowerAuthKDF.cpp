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

#include "PowerAuthKDF.h"

using namespace cc7;
using namespace cc7::crypto;

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

// MARK: - PowerAuthKDF

const std::string PowerAuthKDF::ALG_NAME = "PA4KDF";

PowerAuthKDF::PowerAuthKDF(const cc7::crypto::MACPtr & kmac) : _kmac(kmac)
{
}

ByteArray PowerAuthKDF::derive(const ByteRange & key, const std::string & label, const ByteRange & diversifier, size_t out_size) const
{
    return deriveKeyBytes(key, {
        { PARAM_KEY_CONTEXT,    Parameter::ref(MakeRange(label)) },   // cast to bytes
        { KDF_PARAM_INFO,       Parameter::ref(diversifier) },
        { KDF_PARAM_KEY_SIZE,   Parameter::take(out_size)   }
    });
}

// KeyDerivation interface

ByteArray PowerAuthKDF::deriveKeyBytes(const cc7::ByteRange &key_material, const cc7::crypto::ParameterList &parameters) const
{
    ByteRange key_context, diversifier;
    size_t out_size = 0;
    auto ctx = parameters.beginParameterProcessing();
    if (!parameters.getBytes(PARAM_KEY_CONTEXT, ctx, key_context)) {
        throw std::invalid_argument("Missing PARAM_KEY_CONTEXT parameter");
    }
    if (!parameters.getSize(KDF_PARAM_KEY_SIZE, ctx, out_size)) {
        throw std::invalid_argument("Missing KDF_PARAM_KEY_SIZE parameter");
    }
    parameters.getBytes(KDF_PARAM_INFO, ctx, diversifier);
    parameters.endParameterProcessing(ctx);
    
    if (key_context.empty()) {
        throw std::invalid_argument("Empty PARAM_KEY_CONTEXT parameter");
    }
    if (out_size == 0) {
        throw std::invalid_argument("Invalid KDF_PARAM_KEY_SIZE");
    }
    ByteArray custom;
    custom.reserve(ALG_NAME.size() + 1 + key_context.size());

    custom.assign(MakeRange(ALG_NAME));
    custom.append(':');
    custom.append(key_context);
    
    return _kmac->token(key_material, diversifier, {
        { MAC_PARAM_DIGEST_LENGTH, Parameter::take(out_size) },
        { MAC_PARAM_CUSTOM_DATA,   Parameter::ref(custom)    }
    });
}

// Algorithm interface

const std::string & PowerAuthKDF::getAlgorithmName() const
{
    return ALG_NAME;
}

void PowerAuthKDF::setParameter(int param_id, const Parameter & value)
{
    throw std::invalid_argument("Unsupported parameter");
}

Parameter PowerAuthKDF::getParameter(int param_id) const
{
    throw std::invalid_argument("Unsupported parameter");
}



// MARK: - PowerAuthPassKDF

const std::string PowerAuthPassKDF::ALG_NAME = "PA4PBKDF";

PowerAuthPassKDF::PowerAuthPassKDF(const cc7::crypto::MACPtr & kmac) : _kmac(kmac)
{
}

ByteArray PowerAuthPassKDF::derive(const cc7::ByteRange &key, const cc7::ByteRange &salt, size_t out_size) const
{
    return deriveKeyBytes(key, {
        { KDF_PARAM_SALT,       Parameter::ref(salt)      },
        { KDF_PARAM_KEY_SIZE,   Parameter::take(out_size) }
    });
}

// KeyDerivation interface

ByteArray PowerAuthPassKDF::deriveKeyBytes(const cc7::ByteRange &key_material, const cc7::crypto::ParameterList &parameters) const
{
    ByteRange salt;
    size_t out_size = 0;
    auto ctx = parameters.beginParameterProcessing();
    if (!parameters.getBytes(KDF_PARAM_SALT, ctx, salt)) {
        throw std::invalid_argument("Missing KDF_PARAM_SALT parameter");
    }
    if (!parameters.getSize(KDF_PARAM_KEY_SIZE, ctx, out_size)) {
        throw std::invalid_argument("Missing KDF_PARAM_KEY_SIZE parameter");
    }
    parameters.endParameterProcessing(ctx);
    
    if (salt.size() < 32) {
        throw std::invalid_argument("KDF_PARAM_SALT is too small");
    }
    if (out_size == 0) {
        throw std::invalid_argument("Invalid KDF_PARAM_KEY_SIZE");
    }
    
    return _kmac->token(key_material, salt, {
        { MAC_PARAM_DIGEST_LENGTH, Parameter::take(out_size) },
        { MAC_PARAM_CUSTOM_STRING, Parameter::ref(ALG_NAME)  }
    });
}

// Algorithm interface

const std::string & PowerAuthPassKDF::getAlgorithmName() const
{
    return ALG_NAME;
}

void PowerAuthPassKDF::setParameter(int param_id, const Parameter & value)
{
    throw std::invalid_argument("Unsupported parameter");
}

Parameter PowerAuthPassKDF::getParameter(int param_id) const
{
    throw std::invalid_argument("Unsupported parameter");
}


} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
