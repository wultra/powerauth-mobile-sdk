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

#include "HttpHeaderHelper.h"
#include "model/Constants.h"

namespace powerAuth {

HttpHeader HttpHeaderHelper::buildEncryptionRequestHeader(const EncryptorParameters& parameters)
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

HttpHeader HttpHeaderHelper::buildAuthenticationHeader(const AuthenticationHeaderData& header_data)
{
    std::string proto_version = ProtocolVersion_GetHttpHeaderVersion(header_data.version);
    std::string value;
    value.reserve(120 + proto_version.size() +
                  header_data.applicationKey.size() +
                  header_data.activationIdentifier.size() +
                  header_data.authenticationCode.size() +
                  header_data.authenticationFactors.size());
    value = "PowerAuth pa_version=\"";
    value += proto_version;
    value += "\", pa_application_key=\"";
    value += header_data.applicationKey;
    value += "\", pa_activation_id=\"";
    value += header_data.activationIdentifier;
    if (header_data.version >= Version_V4) {
        value += "\", pa_auth_code_type=\"";
        value += header_data.authenticationFactors;
        value += "\", pa_auth_code=\"";
        value += header_data.authenticationCode;
    } else {
        value += "\", pa_signature_type=\"";
        value += header_data.authenticationFactors;
        value += "\", pa_signature=\"";
        value += header_data.authenticationCode;
    }
    value += "\", pa_nonce=\"";
    value += header_data.nonce;
    value += "\"";
    return { common::PA_AUTHORIZATION_HEADER_NAME, value };
}

HttpHeader HttpHeaderHelper::buildTokenHeader(const TokenHeaderData &header_data)
{
    std::string proto_version = ProtocolVersion_GetHttpHeaderVersion(header_data.version);
    std::string value;
    value.reserve(75 + proto_version.size() +
                  header_data.tokenIdentifier.size() +
                  header_data.tokenDigest.size() +
                  header_data.timestamp.size() +
                  header_data.nonce.size());
    value = "PowerAuth version=\"";
    value += proto_version;
    value += "\", token_id=\"";
    value += header_data.tokenIdentifier;
    value += "\", token_digest=\"";
    value += header_data.tokenDigest;
    value += "\", nonce=\"";
    value += header_data.nonce;
    value += "\", timestamp=\"";
    value += header_data.timestamp;
    value += "\"";
    return { common::PA_TOKEN_HEADER_NAME, value };
}

} // namespace powerAuth
