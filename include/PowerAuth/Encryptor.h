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

#include <PowerAuth/Service.h>
#include <PowerAuth/Request.h>
#include <cc7/crypto/Crypto.h>
#include <cc7/json/Json.h>

namespace powerAuth {

// MARK: - Encryptor specification

/// The `EncryptorSpec` structure contains all information for proper End-To-End encryptor
/// construction.
struct EncryptorSpec
{
    /// Encryptor's identifier.
    const EncryptorId identifier;
    /// Encryptor's scope.
    const EncryptorScope scope;
    /// String representation of encryptor's ID.
    const std::string identifierName;
    /// Pre-agreed shared info 1 constant.
    const std::string sharedInfo1;
    /// Encryptor's flags.
    const cc7::U32 flags;
    
    /// Returns `true` if encryptor is activation scoped.
    bool isActivationScoped() const noexcept;
    /// Returns `true` if encryptor is application scoped.
    bool isApplicationScoped() const noexcept;
    /// Checks whether the encryptor is available in given protocol version.
    bool isAvailableInProtocol(ProtocolVersion version) const noexcept;
    
    /// Get encryptor's specification.
    /// - Parameter identifier: Encryptor to find.
    /// - Returns: Encryptor's specification.
    /// - Throws: `Exception` with `EC_NotAllowed` if `EncryptorId::NONE` is requested.
    static EncryptorSpec const * const specForId(EncryptorId identifier);
    
    /// Find encryptor specification by string representation of encryptor's ID.
    /// - Parameter identifier_name: Encryptor's identifier in string representation.
    /// - Returns: Encryptor's specification.
    /// - Throws: `Exception` with `EC_WrongParameter` if no such encryptor exists.
    static EncryptorSpec const * const specForName(const std::string & identifier_name);
};

typedef EncryptorSpec const * const EncryptorSpecPtr;


// MARK: - Request - Response


/// The `EncryptedRequest` structure represents encrypted request data.
struct EncryptedRequest
{
    /// JSON with request cryptogram. The content depend's on protocol version.
    cc7::json::JsonValue requestPayload;
    /// List of headers that should be used in HTTP request.
    HttpHeaderList requestHeaders;
};

/// The `EncryptedResponse` structure represents encrypted response data received
/// from the server.
struct EncryptedResponse
{
    /// JSON with response cryptogram. The content depend's on protocol version.
    cc7::json::JsonValue responsePayload;
};


// MARK: - Encryptors

/// The `IClientEncryptor` class defines an abstract interface for encrypting requests
/// and decrypting responses. To create an instance implementing this interface,
/// use the `IEncryptorFactory` interface.
///
/// The encryptor is always "one-shot": each instance can encrypt only one request
/// and decrypt only one response received from the server. For additional requests,
/// a new encryptor instance must be created.
class IClientEncryptor
{
public:
    /// Default destructor.
    virtual ~IClientEncryptor() = default;
    
    /// Returns `true` if encryptor is ready to encrypt the request.
    virtual bool canEncryptRequest() const noexcept = 0;
    
    /// Returns `true` if encryptor is ready to decrypt the response.
    virtual bool canDecryptResponse() const noexcept = 0;
    
    /// Encrypt the request data.
    /// - Parameter data: Data to encrypt.
    /// - Returns: Encrypted request.
    /// - Throws: `Exception` in case of failure.
    virtual EncryptedRequest encryptRequest(const cc7::ByteRange& data) = 0;

    /// Decrypt the response received from the server.
    /// - Parameter response: Response received from the server.
    /// - Returns: Decrypted data.
    /// - Throws: `Exception` in case of failure.
    virtual cc7::ByteArray decryptResponse(const EncryptedResponse& response) = 0;
    
    /// The convenient method that encrypt the request data in form of JSON representation.
    /// - Parameters:
    ///   - json: Request data in JSON representation.
    ///   - options: JSON serialization options. By default `cc7::json::JsonWriter::Default` is used.
    /// - Returns: Encrypted request.
    /// - Throws: `Exception` in case of failure.
    EncryptedRequest encryptJsonRequest(const cc7::json::JsonValue& json, int options = cc7::json::JsonWriter::Default);
    
    /// The convenient method that decrypt the response data received from the server into
    /// JSON representation.
    ///
    /// - Parameter response: Response received from the server.
    /// - Returns: Decrypted data in JSON representation.
    /// - Throws: `Exception` in case of failure.
    cc7::json::JsonValue decryptJsonResponse(const EncryptedResponse& response);
};

CC7_SHARED_PTR(IClientEncryptor)

/// The `IServerEncryptor` class defines an abstract interface for decrypting requests
/// received from the client and encrypting responses. The method is used only
/// as a counterpart to `IClientEncryptor` in unit tests.
///  
/// The encryptor is always "one-shot": each instance can decrypt only one request received
/// from the client and encrypt only one response. For additional requests, a new encryptor
/// instance must be created.
class IServerEncryptor
{
public:
    
    /// Default destructor.
    virtual ~IServerEncryptor() = default;
    
    /// Returns `true` if encryptor is ready to decrypt the request received from the client.
    virtual bool canDecryptRequest() const noexcept = 0;
    
    /// Returns `true` if encryptor is ready to encrypt the response for the client.
    virtual bool canEncryptResponse() const noexcept = 0;
    
    /// Decrypt the request received from the client.
    /// - Parameter request: Request cryptogram.
    /// - Returns: Decrypted data.
    /// - Throws: `Exception` in case of failure.
    virtual cc7::ByteArray decryptRequest(const EncryptedRequest& request) = 0;
    
    /// Encrypt the response for the client.
    /// - Parameter data: Data to encrypt.
    /// - Returns: Encrypted response.
    /// - Throws: `Exception` in case of failure.
    virtual EncryptedResponse encryptResponse(const cc7::ByteRange& data) = 0;
    
    /// The convenient method that cecrypt the request received from the client and return
    /// JSON representation of the received data.
    /// - Parameter request: Encrypted request.
    /// - Returns:
    /// - Throws: `Exception` in case of failure.
    cc7::json::JsonValue decryptJsonRequest(const EncryptedRequest& request);
    
    /// Encrypt the response for the client. The response is in form of JSON representation.
    /// - Parameters:
    ///   - json: Response in form of JSON representation
    ///   - options: JSON serialization options.
    /// - Returns: Encrypted response.
    /// - Throws: `Exception` in case of failure.
    EncryptedResponse encryptJsonResponse(const cc7::json::JsonValue& json, int options = cc7::json::JsonWriter::Default);
};

CC7_SHARED_PTR(IServerEncryptor)

// MARK: - EncryptorFactory

/// The `IClientEncryptorFactory` service provides interface for creating objects implementing
/// `IClientEncryptor` interface. The service also provides functionality to fetch the temporary
/// encryption keys from the server.
class IClientEncryptorFactory
{
public:
    
    /// Default destructor.
    virtual ~IClientEncryptorFactory() = default;
    
    /// Return instance of this `IClientEncryptorFactory` implementing `IService` interface.
    /// This means that class implementing the factory interface must be also a service.
    virtual IServicePtr asService() = 0;
    
    /// Removes all keys from the service.
    /// - Throws:
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual void resetAllData() = 0;
    
    /// Removes all activation related keys from the service.
    /// - Throws:
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual void resetActivationData() = 0;

    /// Determine whether the temporary key for selected scope is stored in the service and is valid.
    /// - Parameter scope: Scope of the key.
    /// - Returns: `true` if key for given scope is stored in the service and is still valid.
    /// - Throws:
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual bool hasTemporaryKey(EncryptorScope scope) = 0;
    
    /// Delete the temporary key for given scope stored in the service.
    /// - Parameter scope: Scope of the key to delete.
    /// - Throws:
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual void deleteTemporaryKey(EncryptorScope scope) = 0;
    
    /// Create request for getting the temporary key with given scope from the server.
    /// - Parameter scope: Scope of the key to fetch.
    /// - Returns: Request object with data for fetching the key from the server.
    /// - Throws:
    ///   - `Exception` with `EC_NotAllowed` if there's already pending request.
    ///   - `Exception` with `EC_MissingActivation` if activation scoped key is requested but Session has
    ///      no activation.
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual RequestPtr getTemporaryKeyRequest(EncryptorScope scope) = 0;
    
    /// Get information whether there's already pending request for getting the temporary key.
    /// - Parameter scope: Scope of the key.
    /// - Returns: `true` if there's pending request for getting the temporary key for given scope.
    /// - Throws:
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual bool hasPendingTemporaryKeyRequest(EncryptorScope scope) = 0;

    /// Create encryptor implementation for given encryptor identifier.
    /// - Parameter encryptor_id: Encryptor's identifier.
    /// - Returns: shared pointer with `IClientEncryptor` implementation.
    /// - Throws:
    ///   - `Exception` with `EC_MissingActivation` if encryptor is activation scoped and Session has no activation.
    ///   - `Exception` with `EC_NotAllowed` if encryptor identifier is `NONE`.
    ///   - `Exception` with `EC_InternalError` if service is already destroyed.
    virtual IClientEncryptorPtr getClientEncryptor(EncryptorId encryptor_id) = 0;
};

CC7_SHARED_PTR(IClientEncryptorFactory)

/// The `EncryptorSecrets` structure contains secret keys used internally by the encryptors.
struct EncryptorSecrets
{
    /// Encryptor's envelope key. The envelope key is typically a base key used for one
    /// request and response encryption and decryption on both sides of the communication.
    const cc7::ByteArray envelopeKey;
    /// Pre-agreed shared info 2 parameter. The naming notation is adopted from ECIES,
    /// but is also used in our AEAD based encryptors. The value typically depends
    /// on scope of the encryptor.
    const cc7::ByteArray sharedInfo2;
    /// Optional ephemeral key. The value is set only if the encryption scheme use
    /// ephemeral key for each request and response roundtrip.
    const cc7::ByteArray ephemeralKey;
    
    /// Construct secrets from given parameters.
    /// - Parameters:
    ///   - envelope_key: Encryptor's envelope key.
    ///   - shared_info_2: Pre-agreed shared info 2 parameter.
    ///   - ephemeral_key: Optional ephemeral key.
    /// - Returns: Unique pointer with encryptor secrets.
    static std::unique_ptr<EncryptorSecrets> makeSecrets(const cc7::ByteRange& envelope_key,
                                                         const cc7::ByteRange& shared_info_2,
                                                         const cc7::ByteRange& ephemeral_key) noexcept;
};

typedef std::unique_ptr<EncryptorSecrets> EncryptorSecretsPtr;

/// The `EncryptorParameters` structure contains all parameters required for the encryptor construction.
struct EncryptorParameters
{
    /// Protocol version.
    const ProtocolVersion version;
    /// Pointer to encryptor's specification.
    const EncryptorSpecPtr encryptorSpec;
    /// The protocol version in string representation.
    const std::string protocolVersion;
    /// PowerAuth application's key.
    const std::string applicationKey;
    /// PowerAuth application's secret.
    const std::string applicationSecret;
    /// Temporary key identifier.
    const std::string temporaryKeyId;
    /// Optional activation identifier. The value is required in case the encryptor
    /// is activation scoped.
    const std::string activationIdentifier;
    
    /// Returns encryptor's identifier.
    EncryptorId encryptorId() const noexcept
    {
        return encryptorSpec->identifier;
    }
    
    /// Returns shared info 1 value. The naming notation is adopted from ECIES,
    /// but is also used in our AEAD scheme.
    const std::string& sharedInfo1() const noexcept
    {
        return encryptorSpec->sharedInfo1;
    }
    
    /// Function build associated data from this parameters structure.
    cc7::ByteArray buildAssociatedData() const noexcept;
    
    /// Construct encryptor parameters from the given values.
    /// - Parameters:
    ///   - version: Protocol version.
    ///   - encryptorId: Pointer to encryptor's specification.
    ///   - applicationKey: PowerAuth application's key.
    ///   - applicationSecret: PowerAuth application's secret.
    ///   - temporaryKeyId: Temporary key identifier.
    ///   - activationIdentifier: Optional activation identifier. The value is required in case the encryptor is activation scoped.
    /// - Returns: Unique pointer with encryptor parameters.
    /// - Throws:
    ///   - `Exception` with `EC_MissingActivation` if encryptor is activation scoped and Session has no activation.
    ///   - `Exception` with `EC_NotAllowed` if encryptor identifier is `NONE`.
    static std::unique_ptr<EncryptorParameters> makeParameters(ProtocolVersion version,
                                                               EncryptorId encryptorId,
                                                               const std::string& applicationKey,
                                                               const std::string& applicationSecret,
                                                               const std::string& temporaryKeyId,
                                                               const std::string& activationIdentifier);
};

typedef std::unique_ptr<EncryptorParameters> EncryptorParametersPtr;

} // namespace powerAuth
