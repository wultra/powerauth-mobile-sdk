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
#include <PowerAuth/VaultService.h>
#include <cc7/jwt/Jwt.h>

namespace powerAuth {

/// The `SignatureKeySpec` contains information about the key used for
/// signature calculation or verification for the selected `SignatureKeyId`.
struct SignatureKeySpec
{
    /// Key to use for selected operation.
    enum KeyToUse {
        /// Select `KEY_MASTER_*` keys.
        MASTER,
        /// Select `KEY_SERVER_*` keys.
        SERVER,
        /// Select `KEY_DEVICE_*` keys.
        DEVICE,
        /// Select `KEY_MAC_PERSONALIZED_DATA` key.
        MAC
    };
    /// Specifies key storage to use.
    const KeyToUse keyToUse;
    /// If set, only the selected key type is used.
    const std::optional<SignatureKeyType> keyType;
    /// If `true`, the key may be used for data signing.
    const bool sign;
    /// If `true`, the key may be used for signature verification.
    const bool verify;
    /// If `true`, the key is available only when an activation is present.
    const bool requireActivation;
    
    /// Check whether provided key type is included in this specification.
    /// - Parameter key_type: Key type
    bool keyIsIncluded(const std::string& key_type) const;
    
    /// Get the signature specification for a given signature key identifier.
    /// - Parameter key_id: Key identifier
    /// - Returns: Immutable pointer to the signature specification.
    static SignatureKeySpec const * const specForKeyId(SignatureKeyId key_id) noexcept;
    
    /// Get the signature key type for a given string representation of the key algorithm.
    /// - Parameter key_algorithm: String representation of the key algorithm.
    /// - Returns: The matching `SignatureKeyType`.
    /// - Throws: `Exception` with `EC_WrongParameter` if an unknown key algorithm is provided.
    static SignatureKeyType keyTypeForKeyAlgorithm(const std::string& key_algorithm);
};

typedef SignatureKeySpec const * const SignatureKeySpecPtr;

/// The `SignatureService` implements data signing with device private key and signature
/// verification with various public keys. The service provides its functionality for all
/// protocol versions.
class SignatureService :
    public ServiceWithContext,
    public std::enable_shared_from_this<SignatureService>
{
public:
    SignatureService(const std::shared_ptr<Context>& context);
        
    /// Verify a digital signature over the given data.
    ///
    /// - Parameters:
    ///   - signed_data: Signed data.
    ///   - signature: Signature calculated from signed data.
    ///   - key_to_use: Key used for signature verification. The key
    ///                 must support signature verification.
    bool verifySignature(const cc7::ByteRange& signed_data,
                         const cc7::ByteRange& signature,
                         SignatureKeyId key_to_use) const;
    
    /// Create a digital signature over the given data. If the request succeeds, the
    /// response contains a `DataResponse` with the calculated signature.
    /// - Parameters:
    ///   - credentials: Credentials to use to unlock the device private key.
    ///   - data_to_sign: Data to sign.
    ///   - key_to_use: Key used for signature calculation. The key
    ///                 must support signature calculation.
    RequestPtr signData(const CredentialsPtr& credentials,
                        const cc7::ByteRange& data_to_sign,
                        SignatureKeyId key_to_use) const;
    
    /// Verify server-signed data in JWS or JWT form.
    ///
    /// - Parameters:
    ///   - signed_data: JWS or JWT signed data.
    ///   - key_to_use: Key used for the signature verification. The key
    ///                 must support the signature verification.
    ///   - is_compact_form: If `true`, the provided string is a JWT instead of a full JWS object.
    ///   - verify_mode: Specify signature verification mode.
    /// - Returns: `true` if signature is valid.
    bool jwsVerifySignature(const std::string &signed_data,
                            SignatureKeyId key_to_use,
                            bool is_compact_form,
                            cc7::jwt::JwsVerifyMode verify_mode) const;
    
    /// Create a JWS (or compact JWT) over the given data. If the request succeeds, the
    /// response contains a `StringResponse` with the calculated JWS or JWT.
    ///
    /// - Parameters:
    ///   - credentials: Credentials to use to unlock the device private key.
    ///   - data_to_sign: Data to sign and embed into JWS.
    ///   - data_type: Data type set to JOSE header. Use "JWT" or empty string if no type is set.
    ///   - key_to_use: Key used for the signature calculation. The key
    ///                 must support the signature calculation.
    ///   - use_compact_form: If `true`, the result contains a compact JWT string instead of a JWS.
    ///                 If used with hybrid keys, an exception is raised.
    /// - Returns: HTTP request object with the vault unlock operation.
    RequestPtr jwsSignData(const CredentialsPtr& credentials,
                           const cc7::ByteRange& data_to_sign,
                           const std::string& data_type,
                           SignatureKeyId key_to_use,
                           bool use_compact_form) const;

    /// Create an X.509 CSR (Certificate Signing Request) with the given Distinguished Names and
    /// optional Subject Alternative Names, the embedded device public key, and signed with
    /// the device private key.
    ///
    /// - Parameters:
    ///   - credentials: Credentials to use to unlock the device private key.
    ///   - dn_items: Map with distinguished names.
    ///   - san_items: List of additional subject alternative names.
    ///   - key_to_use: Key to use to create CSR.
    /// - Returns: HTTP request object with the vault unlock operation.
    RequestPtr createCSR(const CredentialsPtr& credentials,
                         const std::map<std::string, std::string>& dn_items,
                         const std::vector<std::string>& san_items,
                         SignatureKeyId key_to_use) const;
    
private:
    
    /// Calculate a signature with the device private key.
    /// - Parameters:
    ///   - context: Context object.
    ///   - data_to_sign: Data to sign.
    ///   - spec: Signing key specification.
    ///   - secrets: `ISecretKeys` implementation containing unlocked device private key.
    /// - Returns: `DataResponse` object containing signature data.
    ResponseObjectPtr doSignData(Context& context,
                                 const cc7::ByteRange& data_to_sign,
                                 SignatureKeySpecPtr spec,
                                 ISecretKeys& secrets) const;
    
    /// Calculate a JWS signature with the device private key.
    /// - Parameters:
    ///   - context: Context object.
    ///   - data_to_sign: Data to sign.
    ///   - data_type: Data type set to JOSE header.
    ///   - spec: Signing key specification.
    ///   - use_compact_form: If `true`, then the result will contain compact JWT string instead of JWS.
    ///   - secrets: `ISecretKeys` implementation containing unlocked device private key.
    /// - Returns: `StringResponse` containing the JWS or JWT string.
    ResponseObjectPtr doJwsSignData(Context& context,
                                    const cc7::ByteRange& data_to_sign,
                                    const std::string& data_type,
                                    SignatureKeySpecPtr spec,
                                    bool use_compact_form,
                                    ISecretKeys& secrets) const;
    
    /// Calculate symmetric key for MAC signature verification.
    /// - Parameters:
    ///   - context: Context object.
    /// - Returns: Symmetric key used for MAC signature verification.
    cc7::ByteArray calculateSymmetricKey(Context& context) const;

    /// Type representing a list of pairs containing public key and algorithm for digital signature verification.
    typedef std::vector<std::pair<cc7::crypto::ConstPublicKeyPtr, std::string>> PublicKeysWithVerifier;
    
    /// Type representing a list of pairs containing private key and algorithm for digital signature calculation.
    typedef std::vector<std::pair<cc7::crypto::ConstPrivateKeyPtr, std::string>> PrivateKeysWithSigner;

    /// Populate all public keys matching the provided signature key specification.
    /// - Parameters:
    ///   - context: Context object.
    ///   - spec: Signature key specification.
    ///   - for_jws: If `true`, then JWS algorithm names are returned for verifier.
    /// - Returns: List of public keys paired with signature verification algorithms.
    PublicKeysWithVerifier populatePublicKeys(Context& context, SignatureKeySpecPtr spec, bool for_jws) const;
    
    /// Populate all private keys matching the provided signature key specification.
    /// - Parameters:
    ///   - context: Context object.
    ///   - spec: Signature key specification.
    ///   - secrets: `ISecretKeys` implementation containing unlocked device private key.
    ///   - for_jws: If `true`, then JWS algorithm names are returned for signer.
    /// - Returns: List of private keys paired with signature calculation algorithms.
    PrivateKeysWithSigner populatePrivateKeys(Context& context, SignatureKeySpecPtr spec, ISecretKeys& secrets, bool for_jws) const;
    
    /// Check whether the provided key specification can be used in the current state of the session data.
    /// If validation fails, the function throws an `Exception` with an appropriate error code.
    /// - Parameters:
    ///   - context: Context object.
    ///   - spec: Signature key specification.
    ///   - allow_hybrid_keys: If `true`, then using more than one key is allowed.
    ///   - for_sign: If `true`, check is performed for signing, otherwise for verify.
    void checkSignatureKeySpec(Context& context, SignatureKeySpecPtr spec, bool allow_hybrid_keys, bool for_sign) const;
    
    const std::shared_ptr<SessionData> _session_data;
    const VaultServicePtr _vault_service;
    const cc7::jwt::JwsAlgorithmProviderPtr _jws_provider;
};

CC7_SHARED_PTR(SignatureService)

} // namespace powerAuth
