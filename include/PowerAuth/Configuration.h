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

class Configuration
{
public:
    
    PowerAuthSpec::Algorithm algorithm() const noexcept;
    const std::string& instanceId() const noexcept;
    const std::string& applicationKey() const noexcept;
    const std::string& applicationSecret() const noexcept;
    
    const cc7::ByteArray& applicationKeyBytes() const noexcept;
    const cc7::ByteArray& applicationSecretBytes() const noexcept;
    
    const cc7::ByteArray& ecdsaMasterServerPublicKey() const noexcept;
    const cc7::ByteArray& mldsaMasterServerPublicKey() const noexcept;
    const cc7::ByteArray& legacyMasterServerPublicKey() const noexcept;
    
    const cc7::ByteArray& deviceSpecificData() const noexcept;
    
    void validatePublicKeys() const;
    
    class Builder {
    public:
        Builder(const std::string& sdk_config);
        
        Builder& withInstanceId(const std::string& instance_id);
        Builder& withAlgorithm(PowerAuthSpec::Algorithm algorithm);
        Builder& withDeviceSpecificData(const cc7::ByteRange& data);
        
        std::shared_ptr<Configuration> build() const;
        
    private:
        
        bool loadFromSdkConfig(const std::string& sdk_config);
        
        PowerAuthSpec::Algorithm _algorithm;
        std::string _instance_id;
        cc7::ByteArray _device_specific_data;
        cc7::ByteArray _application_key;
        cc7::ByteArray _application_secret;
        cc7::ByteArray _ecdsa_master_server_public_key;
        cc7::ByteArray _mldsa_master_server_public_key;
        cc7::ByteArray _legacy_master_server_public_key;
    };
    
private:
    
    Configuration(PowerAuthSpec::Algorithm algorithm,
                  const std::string& instance_id,
                  const cc7::ByteArray& device_specific_data,
                  const cc7::ByteArray& application_key,
                  const cc7::ByteArray& application_secret,
                  const cc7::ByteArray& ecdsa_master_server_public_key,
                  const cc7::ByteArray& mldsa_master_server_public_key,
                  const cc7::ByteArray& legacy_master_server_public_key);
    
    const PowerAuthSpec::Algorithm _algorithm;
    const std::string _instance_id;
    const cc7::ByteArray _device_specific_data;
    const cc7::ByteArray _application_key;
    const cc7::ByteArray _application_secret;
    const std::string _application_key_string;
    const std::string _application_secret_string;
    const cc7::ByteArray _ecdsa_master_server_public_key;
    const cc7::ByteArray _mldsa_master_server_public_key;
    const cc7::ByteArray _legacy_master_server_public_key;
};

CC7_SHARED_PTR(Configuration)

} // namespace powerAuth
