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

#include <PowerAuth/VaultService.h>
#include "request/RequestBuilder.h"
#include "Context.h"

#include "v4/PowerAuthKDF.h"
#include "v3/LegacyKDF.h"

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

namespace powerAuth {

VaultService::VaultService(const ContextPtr& context, ProtocolVersion protocol_version) :
    ServiceWithContext(protocol_version == Version_V4 ? "VaultServiceV4" : "VaultServiceV3", context),
    _key_provider(context->getKeyProviderPtr()),
    _protocol_version(protocol_version)
{
}

VaultServicePtr VaultService::getInstance(const std::shared_ptr<Context> &context, ProtocolVersion protocol_version) noexcept
{
    return std::shared_ptr<VaultService>(new VaultService(context, protocol_version));
}

ProtocolVersion VaultService::protocolVersion() const noexcept
{
    return _protocol_version;
}

RequestPtr VaultService::unlockVaultKey(const CredentialsPtr &credentials, VaultKeyType vault_key_type, UnlockVaultKeyReason unlock_reason, Callback callback) const
{
    auto self = shared_from_this();
    auto context = lockContext();
    if (_protocol_version == Version_V4) {
        // Protocol V4
        return RequestBuilder(*context, v4::Endpoint_VaultUnlock)
            .withAuthentication(credentials)
            .withJson(cc7::json::JsonValue::object({
                { "keyIdentifier", cc7::json::JsonValue(vaultKeyTypeToString(vault_key_type)) },
                { "reason",        cc7::json::JsonValue(unlockVaultKeyReasonToString(unlock_reason)) }
            }))
            .withResponseCallback([self, context, vault_key_type, callback](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
                auto vault_encryption_key = response["vaultEncryptionKey"].asBase64();
                return self->processVaultKeyResponse(*context, vault_key_type, vault_encryption_key, callback);
            })
            .build();

    } else {
        // Protocol V3
        if (vault_key_type != VaultKeyType::KEK_DEVICE_PRIVATE) {
            throw Exception(EC_InternalError, "V3 supports only KEK_DEVICE_PRIVATE key");
        }
        return RequestBuilder(*context, v3::Endpoint_VaultUnlock)
            .withAuthentication(credentials)
            .withJson(cc7::json::JsonValue::object({
                { "reason",        cc7::json::JsonValue(unlockVaultKeyReasonToString(unlock_reason)) }
            }))
            .withResponseCallback([self, context, vault_key_type, callback](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
                auto vault_encryption_key = response["encryptedVaultEncryptionKey"].asBase64();
                return self->processVaultKeyResponse(*context, vault_key_type, vault_encryption_key, callback);
            })
            .build();
    }
}

ResponseObjectPtr VaultService::processVaultKeyResponse(Context &context, VaultKeyType vault_key_type, const cc7::ByteRange &raw_encryption_key, const Callback &callback) const
{
    LOCK_GUARD();
    auto secret_keys = _key_provider->unlockVaultKey(vault_key_type, raw_encryption_key);
    auto response_object = callback(*_key_provider, *secret_keys);
    _key_provider->lockSecretKeys(secret_keys);
    return response_object;
}

RequestPtr VaultService::fetchVaultEncryptionKey(const CredentialsPtr &credentials, VaultEncryptionKeyId key_id, cc7::U64 index) const
{
    if (_protocol_version == Version_V3 && key_id != VaultEncryptionKeyId::LEGACY) {
        throw Exception(EC_WrongParameter, "Only legacy vault encryption key is supported in protocol V3");
    }
    VaultKeyType key_type;
    switch (key_id) {
        case VaultEncryptionKeyId::ANY_2FA:
            key_type = VaultKeyType::KDK_APP_VAULT_2FA;
            break;
        case VaultEncryptionKeyId::KNOWLEDGE:
            key_type = VaultKeyType::KDK_APP_VAULT_KNOWLEDGE;
            break;
        case VaultEncryptionKeyId::LEGACY:
            key_type = VaultKeyType::KEK_DEVICE_PRIVATE;
            break;
    }
    auto self = shared_from_this();
    auto context = lockContext();
    return unlockVaultKey(credentials, key_type, UnlockVaultKeyReason::FETCH_ENCRYPTION_KEY, [self, context, key_id, index](IKeyProvider& key_provider, ISecretKeys& secret_keys) -> ResponseObjectPtr {
        return self->processVaultEncryptionKeyResponse(*context, secret_keys, key_id, index);
    });
}

cc7::ByteArray VaultService::deriveVaultEncryptionKey(const cc7::ByteRange& key, cc7::U64 index, VaultEncryptionKeyId key_id)
{
    std::string label;
    switch (key_id) {
        case VaultEncryptionKeyId::ANY_2FA:   label = "app/kdf/2fa"; break;
        case VaultEncryptionKeyId::KNOWLEDGE: label = "app/kdf/knowledge"; break;
        case VaultEncryptionKeyId::LEGACY:
            throw Exception(EC_WrongParameter, "Legacy key cannot be derived");
    }
    auto be_index = cc7::ToBigEndian(index);
    return algorithms().v4.kdf().derive(key, label , cc7::MakeRange(be_index));
}

ResponseObjectPtr VaultService::processVaultEncryptionKeyResponse(Context& context, ISecretKeys& secret_keys, VaultEncryptionKeyId key_id, cc7::U64 index) const
{
    cc7::ByteArray vault_key;
    switch (key_id) {
        case VaultEncryptionKeyId::ANY_2FA:
            vault_key = secret_keys.kdkAppVault2FA();
            break;
        case VaultEncryptionKeyId::KNOWLEDGE:
            vault_key = secret_keys.kdkAppVaultKnowledge();
            break;
        case VaultEncryptionKeyId::LEGACY:
            // In V3 key provider, KEK_DEVICE_PRIVATE is equal to KEY_ENCRYPTION_VAULT
            vault_key = algorithms().v3.kdf().derive(secret_keys.kekDevicePrivate(), index);
            break;
    }
    return std::make_shared<DataResponse>(vault_key);
}

std::string VaultService::vaultKeyTypeToString(VaultKeyType key_type)
{
    switch (key_type) {
        case VaultKeyType::KEK_DEVICE_PRIVATE:
            return "KEK_DEVICE_PRIVATE";
        case VaultKeyType::KDK_APP_VAULT_2FA:
            return "KDK_APP_VAULT_2FA";
        case VaultKeyType::KDK_APP_VAULT_KNOWLEDGE:
            return "KDK_APP_VAULT_KNOWLEDGE";
    }
}

std::string VaultService::unlockVaultKeyReasonToString(UnlockVaultKeyReason reason)
{
    switch (reason) {
        case UnlockVaultKeyReason::SIGN_WITH_DEVICE_PRIVATE_KEY:
            return "SIGN_WITH_DEVICE_PRIVATE_KEY";
        case UnlockVaultKeyReason::FETCH_ENCRYPTION_KEY:
            return "FETCH_ENCRYPTION_KEY";
        case UnlockVaultKeyReason::LEGACY_ADD_BIOMETRY:
            return "ADD_BIOMETRY";
    }
}

} // namespace powerAuth
