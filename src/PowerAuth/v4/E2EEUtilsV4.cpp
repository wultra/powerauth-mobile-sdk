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

#include "E2EEUtilsV4.h"
#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>
#include "../model/Constants.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

ByteArray E2EE_BuildAssociatedData(const EncryptorParameters& parameters) noexcept
{
    if (parameters.activationIdentifier.empty()) {
        // Application scope
        return utils::ByteUtils_Join({
            MakeRange(parameters.protocolVersion),          // VERSION
            MakeRange(parameters.applicationKey),           // APPLICATION_KEY
            MakeRange(parameters.temporaryKeyId)            // TEMPORARY_KEY_ID
        });
    } else {
        // Activation scope
        return utils::ByteUtils_Join({
            MakeRange(parameters.protocolVersion),          // VERSION
            MakeRange(parameters.applicationKey),           // APPLICATION_KEY
            MakeRange(parameters.activationIdentifier),     // ACTIVATION_ID
            MakeRange(parameters.temporaryKeyId)            // TEMPORARY_KEY_ID
        });
    }
}

HttpHeader E2EE_BuildRequestHeader(const EncryptorParameters& parameters) noexcept
{
    std::string value;
    value.reserve(60 + parameters.protocolVersion.size() + parameters.applicationKey.size() + parameters.activationIdentifier.size());
    value = "PowerAuth version=\"";
    value += parameters.protocolVersion;
    value += "\", application_key=\"";
    value += parameters.applicationKey;
    if (!parameters.activationIdentifier.empty()) {
        value += "\", activation_id=\"";
        value += parameters.activationIdentifier;
    }
    value += "\"";
    return { common::PA_ENCRYPTION_HEADER_NAME, value };
}

EncryptorSecretsPtr E2EE_ApplicationScopeSecrets(const cc7::ByteRange& envelope_key,
                                                 const cc7::ByteRange& application_secret)
{
    auto sh2 = algorithms().v4.sha3_256().digest(application_secret);
    return EncryptorSecrets::makeSecrets(envelope_key, sh2);
}

EncryptorSecretsPtr E2EE_ActivationScopeSecrets(const cc7::ByteRange& envelope_key,
                                                const cc7::ByteRange& application_secret,
                                                const cc7::ByteRange& e2ee_shared_info2_key)
{
    static const std::string KMAC_LABEL("PA4SH2");
    static const cc7::crypto::ParameterList KMAC_PARAMS {
        { MAC_PARAM_CUSTOM_STRING, Parameter::ref(KMAC_LABEL) }
    };
    auto sh2 = algorithms().v4.kmac256().token(e2ee_shared_info2_key, application_secret, KMAC_PARAMS);
    return EncryptorSecrets::makeSecrets(envelope_key, sh2);
}

} // namespace v4
} // namespace powerAuth
