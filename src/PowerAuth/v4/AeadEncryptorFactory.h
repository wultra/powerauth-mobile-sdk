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
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class AeadEncryptorFactory :
    public IEncryptorFactory,
    public std::enable_shared_from_this<AeadEncryptorFactory>
{
public:
    
    AeadEncryptorFactory(Context& context);
    
    void resetAllData() override;
    void resetActivationData() override;
    
    bool hasTemporaryKey(EncryptorScope scope) noexcept override;
    void deleteTemporaryKey(EncryptorScope scope) override;
    
    RequestPtr getTemporaryKeyRequest(Context& context, EncryptorScope scope) override;
    bool hasPendingTemporaryKeyRequest(EncryptorScope scope) noexcept override;
    
    IClientEncryptorPtr getClientEncryptor(EncryptorId encryptor_id) override;

private:
    /// We don't want to use the key that's close to its expiration on the server. This constant specifies for how much
    /// we move the expiration time to backward.
    static const Timestamp KEY_EXPIRATION_THRESHOLD;
    
    /// Size of challenge for getting temporary key.
    static const size_t GET_TEMP_KEY_CHALLENGE_SIZE;
    
    struct GetTemporaryKeyRequest
    {
        std::string applicationKey;
        std::string activationId;
        std::string challenge;
        SharedSecretRequest sharedSecretRequest;
        
        cc7::json::JsonValue toJson() const noexcept;
    };

    struct GetTemporaryKeyResponse
    {
        std::string applicationKey;
        std::string activationId;
        std::string challenge;
        std::string keyId;
        SharedSecretResponse sharedSecretResponse;
        int64_t expiration = 0;
        int64_t serverTime = 0;
        
        static GetTemporaryKeyResponse fromJson(const cc7::json::JsonValue& json);
    };
    
    struct GetKeyData
    {
        TimeService::TaskId timeSynchronization;
        GetTemporaryKeyRequest request;
        SharedSecretContextPtr sharedSecretContext;
    };

    struct TemporaryKeyData
    {
        const EncryptorScope keyScope;
        cc7::crypto::NonceGeneratorPtr nonceGenerator;
        
        std::unique_ptr<GetKeyData> creationData;
        
        std::string keyIdentifier;
        cc7::ByteArray sharedSecret;
        TimeInterval created = -1.0;
        TimeInterval expires = -1.0;
        
        bool isValid() const noexcept;
        bool isExpired(TimeInterval now) const noexcept;
        void clear() noexcept;
        
        bool hasPendingRequest() const noexcept;
    };
    
    const TemporaryKeyData& keyInfo(EncryptorScope scope) const noexcept;
    TemporaryKeyData& keyInfo(EncryptorScope scope) noexcept;
    
    TemporaryKeyData& validKeyInfo(EncryptorScope scope);
    
    void clearDataForScope(EncryptorScope scope, bool key_data_only);
    
    cc7::json::JsonValue createTemporaryKeyRequest(EncryptorScope scope);
    void completeTemporaryKeyRequest(EncryptorScope scope, const cc7::json::JsonValue & response);
    void cancelPendingTemporaryKeyRequest(EncryptorScope scope);
    std::string activationId() const noexcept;
    
    const SharedMutexPtr _lock;
    const ConfigurationPtr _configuration;
    const SessionDataPtr _session_data;
    const IKeyProviderPtr _key_provider;
    const TimeServicePtr _time_service;
    const ISharedSecretPtr _shared_secret_algorithm;
    
    TemporaryKeyData _application_key_info;
    TemporaryKeyData _activation_key_info;

};

} // namespace v4
} // namespace powerAuth

