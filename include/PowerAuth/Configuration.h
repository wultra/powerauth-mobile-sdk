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

#include <cc7/ByteArray.h>
#include <PowerAuth/Exception.h>
#include <PowerAuth/PowerAuthSpec.h>

namespace powerAuth {


/// The `Configuration` class contains configuration for `Session` object.
class Configuration
{
public:
    /// Contains PowerAuth algorithm used in the instance.
    PowerAuthSpec::Algorithm algorithm() const noexcept;
    
    /// Contains instance identifier.
    const std::string& instanceId() const noexcept;
    
    /// Contains PowerAuth application's key in Base64 format.
    const std::string& applicationKey() const noexcept;
    
    /// Contains PowerAuth application's secret in Base64 format.
    const std::string& applicationSecret() const noexcept;
    
    /// Contains PowerAuth application's key.
    const cc7::ByteArray& applicationKeyBytes() const noexcept;
    
    /// Contains PowerAuth application's secret.
    const cc7::ByteArray& applicationSecretBytes() const noexcept;
    
    /// Contains P-384 master server's public key.
    const cc7::ByteArray& p384MasterServerPublicKey() const noexcept;
    
    /// Contains ML-DSA-65 master server's public key.
    const cc7::ByteArray& mldsa65MasterServerPublicKey() const noexcept;
    
    /// Contains ML-DSA-87 master server's public key.
    const cc7::ByteArray& mldsa87MasterServerPublicKey() const noexcept;
    
    /// Contains legacy P-256 master server's public key.
    const cc7::ByteArray& p256MasterServerPublicKey() const noexcept;
    
    /// Contains device specific data.
    const cc7::ByteArray& deviceSpecificData() const noexcept;
    
    /// Return master server public key with given key identifier. If key is not set,
    /// then returns reference to empty array.
    /// - Parameter key_id: Key identifier.
    /// - Returns: Reference to key data.
    const cc7::ByteArray& masterServerPublicKeyWithId(PowerAuthSpec::MasterKeyId key_id) const noexcept;
    
    /// Validate public keys and throw exception if some required key is invalid.
    /// - Throws: `Exception` with `EC_InvalidData` if some key is invalid.
    void validatePublicKeys() const;
    
    /// The `Builder` class build and validate `Configuration`.
    class Builder {
    public:
        /// Construct builder with SDK configuration string.
        /// - Parameter sdk_config: SDK configuration string.
        /// - Parameter algorithm: Algorithm to use.
        /// - Throws: `Exception` with `EC_InvalidData` if configuration string is invalid.
        Builder(const std::string& sdk_config, PowerAuthSpec::Algorithm algorithm = PowerAuthSpec::EC_P384_ML_L3);
        
        /// Configure device specific data. This parameter is required for `Configuration` construction.
        ///
        /// The device specific data affects KEK (key encryption key) protecting possession factor.
        ///
        /// - Parameter data: Required device specific data.
        /// - Returns: Builder reference.
        Builder& withDeviceSpecificData(const cc7::ByteRange& data);
        
        /// Configure instance identifier for future `Configuration` object. If instance identifier
        /// is not specified, then `"default"` string is applied to future configuration.
        ///
        /// - Parameter data: Device specific data.
        /// - Returns: Builder reference.
        Builder& withInstanceId(const std::string& instance_id);
        
        /// Build configuration from given parameters.
        ///
        /// Be aware that this method doesn't validate whether public keys are valid. The validation must be
        /// performed afterwards by calling `validatePublicKeys()` on created instance of configuration.
        ///
        /// - Returns: Shared pointer with `Configuration` instance.
        /// - Throws:
        ///   - `Exception` with `EC_WrongParameter` if some required parameter is missing or has unsupported value.
        std::shared_ptr<Configuration> build() const;
        
    private:
        
        /// Load configuration string into internal properties.
        /// - Parameter sdk_config: SDK configuration string.
        /// - Throws:
        ///   - `Exception` with `EC_InvalidData` if invalid configuration provided.
        void loadFromSdkConfig(const std::string& sdk_config);
        
        /// Validates presence of public keys, depending on selected algorithm.
        /// - Throws:
        ///   - `Exception` with `EC_InvalidData` if invalid configuration provided.
        void validatePublicKeysPresence() const;
        
        const PowerAuthSpec::Algorithm _algorithm;
        std::string _instance_id;
        cc7::ByteArray _device_specific_data;
        cc7::ByteArray _application_key;
        cc7::ByteArray _application_secret;
        cc7::ByteArray _p256_master_server_public_key;
        cc7::ByteArray _p384_master_server_public_key;
        cc7::ByteArray _mldsa65_master_server_public_key;
        cc7::ByteArray _mldsa87_master_server_public_key;
    };
    
private:
    
    Configuration(PowerAuthSpec::Algorithm algorithm,
                  const std::string& instance_id,
                  const cc7::ByteArray& device_specific_data,
                  const cc7::ByteArray& application_key,
                  const cc7::ByteArray& application_secret,
                  const cc7::ByteArray& p256_master_server_public_key,
                  const cc7::ByteArray& p384_master_server_public_key,
                  const cc7::ByteArray& mldsa65_master_server_public_key,
                  const cc7::ByteArray& mldsa87_master_server_public_key);
    
    const PowerAuthSpec::Algorithm _algorithm;
    const std::string _instance_id;
    const cc7::ByteArray _device_specific_data;
    const cc7::ByteArray _application_key;
    const cc7::ByteArray _application_secret;
    const std::string _application_key_string;
    const std::string _application_secret_string;
    const cc7::ByteArray _p256_master_server_public_key;
    const cc7::ByteArray _p384_master_server_public_key;
    const cc7::ByteArray _mldsa65_master_server_public_key;
    const cc7::ByteArray _mldsa87_master_server_public_key;
};

CC7_SHARED_PTR(Configuration)

} // namespace powerAuth
