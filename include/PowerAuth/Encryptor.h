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

#include <PowerAuth/Request.h>
#include <cc7/crypto/Crypto.h>
#include <cc7/json/Json.h>

namespace powerAuth {

// MARK: - Encryptor specification

enum class EncryptorId
{
    NONE,
    APPLICATION_SCOPE_GENERIC,
    ACTIVATION_SCOPE_GENERIC,
    ACTIVATION_LAYER_2,
    UPGRADE,
    VAULT_UNLOCK,
    CREATE_TOKEN
};

enum class EncryptorScope
{
    APPLICATION,
    ACTIVATION
};

struct EncryptorSpec
{
    const EncryptorId identifier;
    const EncryptorScope scope;
    const std::string identifierName;
    const std::string sharedInfo;
    const cc7::U32 flags;
    
    bool isActivationScoped() const noexcept;
    bool isApplicationScoped() const noexcept;
    bool isAvailableInProtocol(ProtocolVersion version) const noexcept;
    
    static EncryptorSpec const * const specForId(EncryptorId identifier);
    static EncryptorSpec const * const specForName(const std::string & identifier_name);
    static EncryptorSpec const * const specForSharedInfo(const std::string & shared_info);
};

typedef EncryptorSpec const * const EncryptorSpecPtr;

// MARK: - Request - Response

struct EncryptedRequest
{
    cc7::json::JsonValue requestPayload;
    std::vector<HttpHeader> requestHeaders;
};


struct EncryptedResponse
{
    cc7::json::JsonValue responsePayload;
};

// MARK: - Encryptors

class IClientEncryptor
{
public:
    virtual ~IClientEncryptor() = default;
    
    virtual bool canEncryptRequest() const noexcept = 0;
    virtual bool canDecryptResponse() const noexcept = 0;
    
    virtual EncryptedRequest encryptRequest(const cc7::ByteRange& data) = 0;
    virtual cc7::ByteArray decryptResponse(const EncryptedResponse& response) = 0;
    
    EncryptedRequest encryptJsonRequest(const cc7::json::JsonValue& json, int options = cc7::json::JsonWriter::Default);
    cc7::json::JsonValue decryptJsonResponse(const EncryptedResponse& response);
};

typedef std::shared_ptr<IClientEncryptor> IClientEncryptorPtr;

class IServerEncryptor
{
public:
    virtual ~IServerEncryptor() = default;
    
    virtual bool canDecryptRequest() const noexcept = 0;
    virtual bool canEncryptResponse() const noexcept = 0;
    
    virtual cc7::ByteArray decryptRequest(const EncryptedRequest& request) = 0;
    virtual EncryptedResponse encryptResponse(const cc7::ByteRange& data) = 0;
    
    cc7::json::JsonValue decryptJsonRequest(const EncryptedRequest& request);
    EncryptedResponse encryptJsonResponse(const cc7::json::JsonValue& json, int options = cc7::json::JsonWriter::Default);
};

typedef std::shared_ptr<IServerEncryptor> IServerEncryptorPtr;

// MARK: - EncryptorFactory

class IEncryptorFactory
{
public:
    virtual ~IEncryptorFactory() = default;

    virtual void resetAllData() = 0;
    virtual void resetActivationData() = 0;

    virtual bool hasTemporaryKey(EncryptorScope scope) const noexcept = 0;
    virtual void deleteTemporaryKey(EncryptorScope scope) = 0;
    
    virtual RequestPtr getTemporaryKeyRequest(EncryptorScope scope) = 0;
    virtual bool hasPendingTemporaryKeyRequest(EncryptorScope scope) const = 0;
    
    virtual IClientEncryptorPtr getClientEncryptor(EncryptorId encryptor_id) = 0;
    virtual IServerEncryptorPtr getServerEncryptor(EncryptorId encryptor_id) = 0;
};

typedef std::shared_ptr<IEncryptorFactory> IEncryptorFactoryPtr;


// Common structures

class EncryptorSecrets
{
public:
    const cc7::ByteArray envelopeKey;
    const cc7::ByteArray sharedInfo2;
    
    static std::unique_ptr<EncryptorSecrets> makeSecrets(const cc7::ByteRange& envelope_key,
                                                         const cc7::ByteRange& shared_info_2);
};

typedef std::unique_ptr<EncryptorSecrets> EncryptorSecretsPtr;


class EncryptorParameters
{
public:
    const std::string protocolVersion;
    const std::string applicationKey;
    const std::string temporaryKeyId;
    const std::string sharedInfo1;
    const std::string activationIdentifier;
    
    static std::unique_ptr<EncryptorParameters> makeParameters(const std::string& protocolVersion,
                                                               const std::string& applicationKey,
                                                               const std::string& temporaryKeyId,
                                                               const std::string& sharedInfo1,
                                                               const std::string& activationIdentifier);
};

typedef std::unique_ptr<EncryptorParameters> EncryptorParametersPtr;


} // namespace powerAuth
