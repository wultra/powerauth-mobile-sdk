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

#include <PowerAuth/Configuration.h>
#include <PowerAuth/Algorithms.h>

#include <cc7/utils/DataReader.h>
#include <cc7/Base64.h>

#include "model/Constants.h"

namespace powerAuth {

// MARK: - Configuration

Configuration::Configuration(PowerAuthSpec::Algorithm algorithm,
                             const std::string& instance_id,
                             const cc7::ByteArray& device_specific_data,
                             const cc7::ByteArray& application_key,
                             const cc7::ByteArray& application_secret,
                             const cc7::ByteArray& ecdsa_master_server_public_key,
                             const cc7::ByteArray& mldsa_master_server_public_key,
                             const cc7::ByteArray& legacy_master_server_public_key) :
    _algorithm(algorithm),
    _instance_id(instance_id),
    _device_specific_data(device_specific_data),
    _application_key(application_key),
    _application_secret(application_secret),
    _application_key_string(application_key.base64()),
    _application_secret_string(application_secret.base64()),
    _ecdsa_master_server_public_key(ecdsa_master_server_public_key),
    _mldsa_master_server_public_key(mldsa_master_server_public_key),
    _legacy_master_server_public_key(legacy_master_server_public_key)
{
}

PowerAuthSpec::Algorithm Configuration::algorithm() const noexcept
{
    return _algorithm;
}

const std::string& Configuration::instanceId() const noexcept
{
    return _instance_id;
}

const std::string& Configuration::applicationKey() const noexcept
{
    return _application_key_string;
}

const std::string& Configuration::applicationSecret() const noexcept
{
    return _application_secret_string;
}

const cc7::ByteArray& Configuration::applicationKeyBytes() const noexcept
{
    return _application_key;
}

const cc7::ByteArray& Configuration::deviceSpecificData() const noexcept
{
    return _device_specific_data;
}

const cc7::ByteArray& Configuration::applicationSecretBytes() const noexcept
{
    return _application_secret;
}

const cc7::ByteArray& Configuration::ecdsaMasterServerPublicKey() const noexcept
{
    return _ecdsa_master_server_public_key;
}

const cc7::ByteArray& Configuration::mldsaMasterServerPublicKey() const noexcept
{
    return _mldsa_master_server_public_key;
}

const cc7::ByteArray& Configuration::legacyMasterServerPublicKey() const noexcept
{
    return _legacy_master_server_public_key;
}

void Configuration::validatePublicKeys() const
{
    try {
        algorithms().v3.p256().newPublicKey(_legacy_master_server_public_key, cc7::crypto::KEY_FORMAT_X963);
        algorithms().v4.p384().newPublicKey(_ecdsa_master_server_public_key, cc7::crypto::KEY_FORMAT_X963);
        algorithms().v4.mldsa65key().newPublicKey(_mldsa_master_server_public_key, cc7::crypto::KEY_FORMAT_SPKI);
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidData, "Configuration contains invalid public key");
    }
}

bool Configuration::validateSdkConfig(const std::string& sdk_config) noexcept
{
    try {
        auto foo = Builder(sdk_config);
        return true;
    } catch (Exception & e) {
        return false;
    }
}

// MARK: - Builder

Configuration::Builder::Builder(const std::string &sdk_config) :
    _algorithm(PowerAuthSpec::EC_P384_ML_L3),
    _instance_id("default")
{
    if (!loadFromSdkConfig(sdk_config)) {
        throw Exception(EC_InvalidData, "Invalid SDK configuration string");
    }
}

Configuration::Builder& Configuration::Builder::withInstanceId(const std::string& instance_id)
{
    _instance_id = instance_id;
    return *this;
}

Configuration::Builder& Configuration::Builder::withAlgorithm(PowerAuthSpec::Algorithm algorithm)
{
    _algorithm = algorithm;
    return *this;
}

Configuration::Builder& Configuration::Builder::withDeviceSpecificData(const cc7::ByteRange& data)
{
    _device_specific_data = data;
    return *this;
}

ConfigurationPtr Configuration::Builder::build() const
{
    if (_instance_id.empty()) {
        throw Exception(EC_WrongParameter, "InstanceID is empty");
    }
    if (_device_specific_data.empty()) {
        throw Exception(EC_WrongParameter, "Device specific data not provided");
    }
    if (!PowerAuthSpec::specForAlgorithm(_algorithm)->isActivationSupported()) {
        throw Exception(EC_WrongParameter, "Selected algorithm doesn't support activation process");
    }
    auto instance = new Configuration(_algorithm,
                                      _instance_id,
                                      _device_specific_data,
                                      _application_key,
                                      _application_secret,
                                      _ecdsa_master_server_public_key,
                                      _mldsa_master_server_public_key,
                                      _legacy_master_server_public_key);
    return std::shared_ptr<Configuration>(instance);
}

static const cc7::byte CONFIG_VER  = 0x01;
static const cc7::byte P256_KEY_ID = 0x01;
static const cc7::byte P384_KEY_ID = 0x02;
static const cc7::byte MLDSA65_KEY_ID = 0x03;

bool Configuration::Builder::loadFromSdkConfig(const std::string &sdk_config) noexcept
{
    auto reader = cc7::utils::DataReader(cc7::Base64::decode(sdk_config), true);
    cc7::byte data_version;
    if (!reader.readByte(data_version)) {
        return false;
    }
    if (data_version != CONFIG_VER) {
        return false;
    }
    if (!reader.readData(_application_key, common::APPLICATION_KEY_SIZE) ||
        !reader.readData(_application_secret, common::APPLICATION_SECRET_SIZE)) {
        return false;
    }
    size_t keys_count;
    if (!reader.readCount(keys_count)) {
        return false;
    }
    while (keys_count-- > 0) {
        cc7::byte key_id;
        cc7::ByteRange key_data;
        if (!reader.readByte(key_id) || !reader.readRange(key_data)) {
            return false;
        }
        if (key_id == P256_KEY_ID) {
            _legacy_master_server_public_key = key_data;
        } else if (key_id == P384_KEY_ID) {
            _ecdsa_master_server_public_key = key_data;
        } else if (key_id == MLDSA65_KEY_ID) {
            _mldsa_master_server_public_key = key_data;
        }
    }
    return !(_legacy_master_server_public_key.empty() ||
             _ecdsa_master_server_public_key.empty() ||
             _mldsa_master_server_public_key.empty());
}

} // namespace powerAuth
