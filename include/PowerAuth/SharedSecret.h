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

#include <PowerAuth/PowerAuthSpec.h>
#include <cc7/crypto/Crypto.h>
#include <cc7/json/Json.h>

namespace powerAuth {

/// The `SharedSecretContextPtr` is abstract context object representing a client data required for a proper shared
/// sectet derivation on the client side.
typedef cc7::BaseObjectPtr SharedSecretContextPtr;

/// The `SharedSecretRequest` structure contains request data generated on the client side.
struct SharedSecretRequest
{
    /// The selected algorithm.
    std::string algorithm;
    /// List with encapsulated keys, in Base64 format.
    std::vector<std::string> encapsulationKeys;
    
    /// Make JSON representation from the content of this structure.
    /// - Returns: JSON representation created from this structure.
    cc7::json::JsonValue toJson() const;
    
    /// Create structure from JSON representation.
    /// - Parameter value: Source JSON representation.
    /// - Returns: Structure created from JSON representation.
    static SharedSecretRequest fromJson(const cc7::json::JsonValue& value);
};

/// The `SharedSecretResponse` structure contains response data generated on the server side.
struct SharedSecretResponse
{
    /// List with encapsulated keys, in Base64 format.
    std::vector<std::string> encapsulatedKeys;
    
    /// Make JSON representation from the content of this structure.
    /// - Returns: JSON representation created from this structure.
    cc7::json::JsonValue toJson() const;
    
    /// Create structure from JSON representation.
    /// - Parameter value: Source JSON representation.
    /// - Returns: Structure created from JSON representation.
    static SharedSecretResponse fromJson(const cc7::json::JsonValue& value);
};

/// The `ISharedSecret` abstract class defines interface for deducing the shared secret key
/// between the client and the server.
class ISharedSecret : public cc7::BaseObject
{
public:
    /// Get implementation of `ISharedSecret` for the selected algorithm.
    ///
    /// - Parameter algorithm: Algorithm to select.
    /// - Returns: Smart pointer to selected algorithm implementation.
    /// - Throws: `std::logic_error` in case of algorithm enumeration is not supported.
    static std::shared_ptr<ISharedSecret> getInstance(PowerAuthSpec::Algorithm algorithm);
    
    /// Generate the request cryptogram on the client side. The returned pair contains the request object and the client's context
    /// required form the shared secret deduction once the response from the server is received.
    ///
    /// - Returns: pair with `SharedSecretRequest` structure and the smart pointer with the context, required for the response processing.
    /// - Throws: `std::domain_error` in case the underlying cryptographic operation fails.
    virtual std::pair<SharedSecretRequest, SharedSecretContextPtr> generateRequestCryptogram() const = 0;
    
    /// Generate the response cryptogram from the received request cryptogram. The returned pair contains the response structure and
    /// the calculated secret.
    ///
    /// Note that this function is typically not used in client's part of the process (e.g. is not used by PowerAuth SDK). The method
    /// is typically required only for the testing purposes, when the server's response needs to be created.
    ///
    /// - Parameter request: The request structure.
    /// - Returns: pair with `SharedSecretResponse` structure and the calculated shared secret.
    /// - Throws:
    ///   - `std::invalid_argument` in case the required parameter is missing or the selected algorithm is not supported.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual std::pair<SharedSecretResponse, cc7::ByteArray> generateResponseCryptogram(const SharedSecretRequest & request) const = 0;
    
    
    /// Compute the shared secret on the client's side from given context and the response from the server.
    ///
    /// - Parameter context: The context created in `generateRequestCryptogram()` method.
    /// - Parameter response: The response structure.
    /// - Returns: Shared secret key.
    /// - Throws:
    ///   - `std::invalid_argument` in case the required parameter is missing or the selected algorithm is not supported.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual cc7::ByteArray computeSharedSecret(const SharedSecretContextPtr & context, const SharedSecretResponse & response) const = 0;
    
    // Serialization
    
    /// Store the given context structure into the sequence of bytes.
    ///
    /// > Note: It's not recommended to store the result of this function into the persistent storage. The shared secret establishing is
    /// a very sensitive process and therefore you should keep all related information into the memory only.
    ///
    /// - Parameter context: The context created in `generateRequestCryptogram()` method.
    /// - Returns: Serialized context.
    /// - Throws:
    ///   - `std::invalid_argument` in case the context is not supported by this `ISharedSecret` implementation.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual cc7::ByteArray serializeContext(const SharedSecretContextPtr & context) const = 0;
    
    /// Restore the context object from the previously serialized sequence of bytes.
    ///
    /// - Parameter context_data: Previously serialized data.
    /// - Returns: Restored client's context.
    /// - Throws:
    ///   - `std::invalid_argument` in case the context data is not supported by this `ISharedSecret` implementation.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual SharedSecretContextPtr deserializeContext(const cc7::ByteRange & context_data) const = 0;
    
    
    // Tests
    
    /// Export the context into key-value map for the testing purposes.
    ///
    /// > Note: The function is implemented in DEBUG only build of the library and therefore should be used only for the unit testing purposes.
    ///
    /// - Parameter context: The context created in `generateRequestCryptogram()` method.
    /// - Returns: key-value map with internal representation of the context.
    /// - Throws:
    ///   - `std::logic_error` in case the function is used in non-DEBUG build of the library.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual std::map<std::string, std::string> exportContextForTest(const SharedSecretContextPtr & context) const = 0;
    
    /// Re-create the context from the key-value map for the testing purposes.
    ///
    /// > Warning: The function is implemented in DEBUG only build of the library and therefore should be used only for the unit testing purposes.
    ///
    /// - Parameter context: The context created in `generateRequestCryptogram()` method.
    /// - Returns: Restored client's context.
    /// - Throws:
    ///   - `std::invalid_argument` in case the context is not supported by this `ISharedSecret` implementation.
    ///   - `std::logic_error` in case the function is used in non-DEBUG build of the library.
    ///   - `std::domain_error` in case the underlying cryptographic operation fails.
    virtual SharedSecretContextPtr importContextForTest(const std::map<std::string, std::string> & test_data) const = 0;
};

CC7_SHARED_PTR(ISharedSecret)

} // namespace powerAuth
