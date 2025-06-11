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
#include <PowerAuth/TimeService.h>
#include <PowerAuth/SharedSecret.h>
#include <PowerAuth/Configuration.h>
#include <cc7/crypto/Crypto.h>

namespace powerAuth {

struct GetTemporaryKeyRequest
{
    std::string applicationKey;
    std::string activationId;
    std::string challenge;
    SharedSecretRequest sharedSecretRequest;
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
};

class ClientEncryptor;

class EncryptorFactory
{
public:
    EncryptorFactory(ConfigurationPtr configuration,
                     ISharedSecretPtr shared_secret_algorithm,
                     TimeServicePtr time_service,
                     SharedMutexPtr shared_mutex = nullptr);
    
    void resetAllData();
    void resetActivationData();
    void deleteTemporaryKey(EncryptorScope scope);
    
    void setActivationId(const std::string & activation_id);
    
    // Getting temporary key
    bool hasTemporaryKey(EncryptorScope scope);
    
    GetTemporaryKeyRequest getTemporaryKeyRequest(EncryptorScope scope);
    bool hasPendingTemporaryKeyRequest(EncryptorScope scope) const;
    void completeTemporaryKeyRequest(const GetTemporaryKeyResponse & response);
    void cancelPendingTemporaryKeyRequest(EncryptorScope scope);
    
    // Getting encryptors
    
    std::shared_ptr<ClientEncryptor> getClientEncryptor(EncryptorId encryptor_id);

    /// We don't want to use the key that's close to its expiration on the server. This constant specifies for how much
    /// we move the expiration time to backward.
    static const Timestamp KEY_EXPIRATION_THRESHOLD;
    
    /// Size of challenge for getting temporary key.
    static const size_t GET_TEMP_KEY_CHALLENGE_SIZE;
    
private:
    friend class ClientEncryptor;
     
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
        
        std::shared_ptr<GetKeyData> creationData;
        
        std::string keyIdentifier;
        cc7::ByteArray sharedSecret;
        TimeInterval created = -1.0;
        TimeInterval expires = -1.0;
        
        bool isValid() const;
        bool isExpired(TimeInterval now) const;
        void clear();
        
        bool hasPendingRequest() const;
    };
    
    
    
    const TemporaryKeyData& keyInfo(EncryptorScope scope) const;
    TemporaryKeyData& keyInfo(EncryptorScope scope);

    TemporaryKeyData& validKeyInfo(EncryptorScope scope);

    void clearDataForScope(EncryptorScope scope, bool key_data_only);
    
    const SharedMutexPtr _lock;
    const ConfigurationPtr _configuration;
    const TimeServicePtr _time_service;
    const ISharedSecretPtr _shared_secret_algorithm;
    
    std::string _activation_id;
    
    TemporaryKeyData _application_key_info;
    TemporaryKeyData _activation_key_info;
};

typedef std::shared_ptr<EncryptorFactory> EncryptorFactoryPtr;

} // namespace powerAuth
