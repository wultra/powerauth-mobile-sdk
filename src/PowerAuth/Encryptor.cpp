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

#include <PowerAuth/Encryptor.h>
#include <PowerAuth/ByteUtils.h>

using namespace cc7;

namespace powerAuth {

// MARK: - EncryptorSpec implementation

#define FL_PROTO_V3 (1 << 0)
#define FL_PROTO_V4 (1 << 1)
#define FL_PROTO_ALL (FL_PROTO_V3 | FL_PROTO_V4)

static const EncryptorSpec spec_APPLICATION_SCOPE_GENERIC {
    EncryptorId::APPLICATION_SCOPE_GENERIC, 
    EncryptorScope::APPLICATION,
    "APPLICATION_SCOPE_GENERIC",
    "/pa/generic/application",
    FL_PROTO_ALL
};

static const EncryptorSpec spec_ACTIVATION_SCOPE_GENERIC {
    EncryptorId::ACTIVATION_SCOPE_GENERIC,
    EncryptorScope::ACTIVATION,
    "ACTIVATION_SCOPE_GENERIC",
    "/pa/generic/activation",
    FL_PROTO_ALL
};

static const EncryptorSpec spec_ACTIVATION_LAYER_2 {
    EncryptorId::ACTIVATION_LAYER_2,
    EncryptorScope::APPLICATION,
    "ACTIVATION_LAYER_2",
    "/pa/activation",
    FL_PROTO_ALL
};

static const EncryptorSpec spec_UPGRADE {
    EncryptorId::UPGRADE,
    EncryptorScope::ACTIVATION,
    "UPGRADE",
    "/pa/upgrade",
    FL_PROTO_ALL
};

static const EncryptorSpec spec_VAULT_UNLOCK {
    EncryptorId::VAULT_UNLOCK,
    EncryptorScope::ACTIVATION,
    "VAULT_UNLOCK",
    "/pa/vault/unlock",
    FL_PROTO_ALL
};

static const EncryptorSpec spec_CREATE_TOKEN {
    EncryptorId::CREATE_TOKEN,
    EncryptorScope::ACTIVATION,
    "CREATE_TOKEN",
    "/pa/token/create",
    FL_PROTO_ALL
};

static const EncryptorSpec * spec_list[] = {
    &spec_APPLICATION_SCOPE_GENERIC,
    &spec_ACTIVATION_SCOPE_GENERIC,
    &spec_ACTIVATION_LAYER_2,
    &spec_UPGRADE,
    &spec_VAULT_UNLOCK,
    &spec_CREATE_TOKEN,
};

EncryptorSpecPtr EncryptorSpec::specForId(EncryptorId identifier)
{
    switch (identifier) {
        case EncryptorId::APPLICATION_SCOPE_GENERIC:
            return &spec_APPLICATION_SCOPE_GENERIC;
        case EncryptorId::ACTIVATION_SCOPE_GENERIC:
            return &spec_ACTIVATION_SCOPE_GENERIC;
        case EncryptorId::ACTIVATION_LAYER_2:
            return &spec_ACTIVATION_LAYER_2;
        case EncryptorId::UPGRADE:
            return &spec_UPGRADE;
        case EncryptorId::VAULT_UNLOCK:
            return &spec_VAULT_UNLOCK;
        case EncryptorId::CREATE_TOKEN:
            return &spec_CREATE_TOKEN;
        case EncryptorId::NONE:
            throw Exception(EC_InternalError, "NONE encryptor has no specification");
    }
}

EncryptorSpecPtr EncryptorSpec::specForName(const std::string &identifier_name)
{
    for (int i = 0; i < sizeof(spec_list)/sizeof(spec_list[0]); i++) {
        if (spec_list[i]->identifierName == identifier_name) {
            return spec_list[i];
        }
    }
    return nullptr;
}

EncryptorSpecPtr EncryptorSpec::specForSharedInfo(const std::string &shared_info)
{
    for (int i = 0; i < sizeof(spec_list)/sizeof(spec_list[0]); i++) {
        if (spec_list[i]->sharedInfo == shared_info) {
            return spec_list[i];
        }
    }
    return nullptr;
}

bool EncryptorSpec::isActivationScoped() const noexcept
{
    return scope == EncryptorScope::ACTIVATION;
}

bool EncryptorSpec::isApplicationScoped() const noexcept
{
    return scope == EncryptorScope::APPLICATION;
}

bool EncryptorSpec::isAvailableInProtocol(ProtocolVersion version) const noexcept
{
    switch (version) {
        case Version_V4:
            return (flags & FL_PROTO_V4) == FL_PROTO_V4;
        case Version_V3:
            return (flags & FL_PROTO_V3) == FL_PROTO_V3;
        default:
            return false;
    }
}

// MARK: - IClientEncryptor

EncryptedRequest IClientEncryptor::encryptJsonRequest(const cc7::json::JsonValue& json, int options)
{
    try {
        auto data = cc7::json::JsonWriter::toJsonData(json, options);
        return encryptRequest(data);
    } catch (cc7::json::JsonException & e) {
        throw Exception(EC_WrongParameter, "Wrong JSON object provided", std::current_exception());
    }
}

cc7::json::JsonValue IClientEncryptor::decryptJsonResponse(const EncryptedResponse& response)
{
    auto data = decryptResponse(response);
    try {
        return json::JsonReader::fromJsonData(data);
    } catch (cc7::json::JsonException & e) {
        throw Exception(EC_InvalidData, "Failed to parse decrypted data", std::current_exception());
    }
}


// MARK: - IServerEncryptor

cc7::json::JsonValue IServerEncryptor::decryptJsonRequest(const EncryptedRequest& request)
{
    auto data = decryptRequest(request);
    try {
        return json::JsonReader::fromJsonData(data);
    } catch (cc7::json::JsonException & e) {
        throw Exception(EC_InvalidData, "Failed to parse decrypted data", std::current_exception());
    }

}

EncryptedResponse IServerEncryptor::encryptJsonResponse(const cc7::json::JsonValue& json, int options)
{
    try {
        auto data = cc7::json::JsonWriter::toJsonData(json, options);
        return encryptResponse(data);
    } catch (cc7::json::JsonException & e) {
        throw Exception(EC_WrongParameter, "Wrong JSON object provided", std::current_exception());
    }
}

// MARK: - Secrets & Parameters

EncryptorSecretsPtr EncryptorSecrets::makeSecrets(const cc7::ByteRange& envelope_key,
                                                  const cc7::ByteRange& shared_info_2,
                                                  const cc7::ByteRange& ephemeral_key)
{
    return std::unique_ptr<EncryptorSecrets>(new EncryptorSecrets { envelope_key, shared_info_2, ephemeral_key });
}

EncryptorParametersPtr EncryptorParameters::makeParameters(ProtocolVersion protocolVersion,
                                                           EncryptorId encryptorId,
                                                           const std::string& applicationKey,
                                                           const std::string& applicationSecret,
                                                           const std::string& temporaryKeyId,
                                                           const std::string& activationIdentifier)
{
    auto spec = EncryptorSpec::specForId(encryptorId);
    if (spec->isActivationScoped() && activationIdentifier.empty()) {
        throw Exception(EC_InternalError, "Activation ID is required for activation scoped parameters");
    }
    return std::unique_ptr<EncryptorParameters>(new EncryptorParameters {
        protocolVersion,
        spec,
        ProtocolVersion_GetHttpHeaderVersion(protocolVersion),
        applicationKey,
        applicationSecret,
        temporaryKeyId,
        activationIdentifier
    });
}

cc7::ByteArray EncryptorParameters::buildAssociatedData() const noexcept
{
    if (encryptorSpec->isApplicationScoped()) {
        // Application scope
        return utils::ByteUtils_ConcatWithSizes({
            protocolVersion,          // VERSION
            applicationKey,           // APPLICATION_KEY
            temporaryKeyId            // TEMPORARY_KEY_ID
        });
    } else {
        // Activation scope
        return utils::ByteUtils_ConcatWithSizes({
            protocolVersion,          // VERSION
            applicationKey,           // APPLICATION_KEY
            activationIdentifier,     // ACTIVATION_ID
            temporaryKeyId            // TEMPORARY_KEY_ID
        });
    }
}

} // namespace powerAuth
