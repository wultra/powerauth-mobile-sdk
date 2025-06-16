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

#include "AeadUtils.h"
#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>
#include "../model/Constants.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

static const std::string KMAC_LABEL("PA4SH2");
static const cc7::crypto::ParameterList KMAC_PARAMS {
    { MAC_PARAM_CUSTOM_STRING, Parameter::ref(KMAC_LABEL) }
};

EncryptorSecretsPtr AEAD_BuildSecrets(const EncryptorParameters& parameters,
                                      const cc7::ByteRange& shared_secret,
                                      const cc7::ByteRange& e2ee_shared_info2_key)
{
    auto app_secret_bytes = Base64::decode(parameters.applicationSecret);
    ByteArray sh2;
    if (parameters.encryptorSpec->isApplicationScoped()) {
        sh2 = algorithms().v4.sha3_256().digest(app_secret_bytes);
    } else {
        if (e2ee_shared_info2_key.empty()) {
            throw Exception(EC_InternalError, "e2ee_shared_info2_key not provided for activation scope");
        }
        sh2 = algorithms().v4.kmac256().token(e2ee_shared_info2_key, app_secret_bytes, KMAC_PARAMS);
    }
    return EncryptorSecrets::makeSecrets(shared_secret, sh2, ByteRange());
}

} // namespace v4
} // namespace powerAuth
