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
                             const cc7::ByteArray& p256_master_server_public_key,
                             const cc7::ByteArray& p384_master_server_public_key,
                             const cc7::ByteArray& mldsa65_master_server_public_key,
                             const cc7::ByteArray& mldsa87_master_server_public_key) :
    _algorithm(algorithm),
    _instance_id(instance_id),
    _device_specific_data(device_specific_data),
    _application_key(application_key),
    _application_secret(application_secret),
    _application_key_string(application_key.base64()),
    _application_secret_string(application_secret.base64()),
    _p256_master_server_public_key(p256_master_server_public_key),
    _p384_master_server_public_key(p384_master_server_public_key),
    _mldsa65_master_server_public_key(mldsa65_master_server_public_key),
    _mldsa87_master_server_public_key(mldsa87_master_server_public_key)
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

const cc7::ByteArray& Configuration::p256MasterServerPublicKey() const noexcept
{
    return _p256_master_server_public_key;
}

const cc7::ByteArray& Configuration::p384MasterServerPublicKey() const noexcept
{
    return _p384_master_server_public_key;
}

const cc7::ByteArray& Configuration::mldsa65MasterServerPublicKey() const noexcept
{
    return _mldsa65_master_server_public_key;
}

const cc7::ByteArray& Configuration::mldsa87MasterServerPublicKey() const noexcept
{
    return _mldsa87_master_server_public_key;
}

void Configuration::validatePublicKeys() const
{
    try {
        if (!_p256_master_server_public_key.empty()) {
            algorithms().v3.p256().newPublicKey(_p256_master_server_public_key, cc7::crypto::KEY_FORMAT_X963);
        }
        if (!_p384_master_server_public_key.empty()) {
            algorithms().v4.p384().newPublicKey(_p384_master_server_public_key, cc7::crypto::KEY_FORMAT_X963);
        }
        if (!_mldsa65_master_server_public_key.empty()) {
            algorithms().v4.mldsa65key().newPublicKey(_mldsa65_master_server_public_key, cc7::crypto::KEY_FORMAT_SPKI);
        }
        if (!_mldsa87_master_server_public_key.empty()) {
            algorithms().v4.mldsa87key().newPublicKey(_mldsa87_master_server_public_key, cc7::crypto::KEY_FORMAT_SPKI);
        }
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidData, "Configuration contains invalid public key");
    }
}

const cc7::ByteArray& Configuration::masterServerPublicKeyWithId(PowerAuthSpec::MasterKeyId key_id) const noexcept
{
    static const cc7::ByteArray EMPTY;
    switch (key_id) {
        case PowerAuthSpec::KEY_ID_P256: return _p256_master_server_public_key;
        case PowerAuthSpec::KEY_ID_P384: return _p384_master_server_public_key;
        case PowerAuthSpec::KEY_ID_MLDSA65: return _mldsa65_master_server_public_key;
        case PowerAuthSpec::KEY_ID_MLDSA87: return _mldsa87_master_server_public_key;
        default:
            return EMPTY;
    }
}

// MARK: - Builder

Configuration::Builder::Builder(const std::string &sdk_config, PowerAuthSpec::Algorithm algorithm) :
    _algorithm(algorithm),
    _instance_id("default")
{
    loadFromSdkConfig(sdk_config);
}

Configuration::Builder& Configuration::Builder::withInstanceId(const std::string& instance_id)
{
    _instance_id = instance_id;
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
                                      _p256_master_server_public_key,
                                      _p384_master_server_public_key,
                                      _mldsa65_master_server_public_key,
                                      _mldsa87_master_server_public_key);
    return std::shared_ptr<Configuration>(instance);
}

static const cc7::byte CONFIG_VER  = 0x01;

void Configuration::Builder::loadFromSdkConfig(const std::string &sdk_config)
{
    std::string error_message;
    do {
        auto reader = cc7::utils::DataReader(cc7::Base64::decode(sdk_config), true);
        cc7::byte data_version;
        if (!reader.readByte(data_version)) {
            error_message = "Invalid SDK configuration string";
            break;
        }
        if (data_version != CONFIG_VER) {
            error_message = "Unsupported configuration version";
            break;
        }
        if (!reader.readData(_application_key, common::APPLICATION_KEY_SIZE) ||
            !reader.readData(_application_secret, common::APPLICATION_SECRET_SIZE)) {
            error_message = "Invalid SDK configuration string";
            break;
        }
        size_t keys_count;
        if (!reader.readCount(keys_count)) {
            error_message = "Invalid SDK configuration string";
            break;
        }
        while (keys_count-- > 0) {
            cc7::byte key_id;
            cc7::ByteRange key_data;
            if (!reader.readByte(key_id) || !reader.readRange(key_data)) {
                error_message = "Invalid SDK configuration string";
                break;
            }
            if (key_id == PowerAuthSpec::KEY_ID_P256) {
                _p256_master_server_public_key = key_data;
            } else if (key_id == PowerAuthSpec::KEY_ID_P384) {
                _p384_master_server_public_key = key_data;
            } else if (key_id == PowerAuthSpec::KEY_ID_MLDSA65) {
                _mldsa65_master_server_public_key = key_data;
            } else if (key_id == PowerAuthSpec::KEY_ID_MLDSA87) {
                _mldsa87_master_server_public_key = key_data;
            }
        }
    } while (false);
    
    if (!error_message.empty()) {
        throw Exception(EC_InvalidData, error_message);
    }
    validatePublicKeysPresence();
}

void Configuration::Builder::validatePublicKeysPresence() const
{
    auto req_p256 = false;
    auto req_p384 = false;
    auto req_mldsa65 = false;
    auto req_mldsa87 = false;
    switch (_algorithm) {
        case PowerAuthSpec::LEGACY_P256:
            req_p256 = true;
            break;
        case PowerAuthSpec::EC_P384:
            req_p256 = req_p384 = true;
            break;
        case PowerAuthSpec::EC_P384_ML_L3:
            req_p256 = req_p384 = req_mldsa65 = true;
            break;
        case PowerAuthSpec::EC_P384_ML_L5:
            req_p256 = req_p384 = req_mldsa87 = true;
            break;
        case PowerAuthSpec::ML_L3:
            req_p256 = req_mldsa65 = true;
            break;
        case PowerAuthSpec::ML_L5:
            req_p256 = req_mldsa87 = true;
            break;
        default:
            throw Exception(EC_InternalError, "Algorithm not supported in configuration");
    }
    std::string missing_key;
    if (req_p256 && _p256_master_server_public_key.empty()) {
        missing_key = "KEY_MASTER_P256_PUBLIC";
    } else if (req_p384 && _p384_master_server_public_key.empty()) {
        missing_key = "KEY_MASTER_ECDSA_P384_PUBLIC";
    } else if (req_mldsa65 && _mldsa65_master_server_public_key.empty()) {
        missing_key = "KEY_MASTER_MLDSA65_PUBLIC";
    } else if (req_mldsa87 && _mldsa87_master_server_public_key.empty()) {
        missing_key = "KEY_MASTER_MLDSA87_PUBLIC";
    }
    if (!missing_key.empty()) {
        auto& algorithm_name = PowerAuthSpec::specForAlgorithm(_algorithm)->algorithmName();
        // Example error message:
        // Configuration is missing KEY_MASTER_ECDSA_P384_PUBLIC key required for EC_P384 algorithm
        throw Exception(EC_InvalidData, "Configuration is missing " + missing_key +
                                        " key required for " + algorithm_name +
                                        " algorithm");
    }
}

} // namespace powerAuth
