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

#include "PersistentData.h"

#include <PowerAuth/Exception.h>
#include <PowerAuth/PowerAuthSpec.h>

namespace powerAuth {

PersistentData::PersistentData(std::unique_ptr<V3>& v3, bool modified) :
    _version(Version_V3),
    _v3(std::move(v3)),
    _modified(modified)
{
}

PersistentData::PersistentData(std::unique_ptr<V4>& v4, bool modified) :
    _version(Version_V4),
    _v4(std::move(v4)),
    _modified(modified)
{
}


PersistentDataPtr PersistentData::create(std::unique_ptr<V4> &v4)
{
    if (!v4 || !validateV4(*v4)) {
        throw Exception(EC_InternalError, "V4 data invalid");
    }
    return std::unique_ptr<PersistentData>(new PersistentData(v4, true));
}

PersistentDataPtr PersistentData::create(std::unique_ptr<V3> &v3)
{
    if (!v3 || !validateV3(*v3)) {
        throw Exception(EC_InternalError, "V3 data invalid");
    }
    return std::unique_ptr<PersistentData>(new PersistentData(v3, true));
}

ProtocolVersion PersistentData::getProtocolVersion() const noexcept
{
    return _version;
}

const std::string& PersistentData::getActivationId() const noexcept
{
    return (_version == Version_V4) ? _v4->activationId : _v3->activationId;
}

PersistentData::V3& PersistentData::v3()
{
    if (_v3 == nullptr) {
        throw Exception(EC_InternalError, "V3 data not available");
    }
    _modified = true;
    return *_v3;
}

const PersistentData::V3& PersistentData::v3() const
{
    if (_v3 == nullptr) {
        throw Exception(EC_InternalError, "V3 data not available");
    }
    return *_v3;
}

PersistentData::V4& PersistentData::v4()
{
    if (_version != Version_V4) {
        throw Exception(EC_NotAllowed, "V4 data not available");
    }
    _modified = true;
    return *_v4;
}

const PersistentData::V4& PersistentData::v4() const
{
    if (_version != Version_V4) {
        throw Exception(EC_NotAllowed, "V4 data not available");
    }
    return *_v4;
}

bool PersistentData::isModified() const noexcept
{
    return _modified;
}

// Serialization

static const cc7::byte PD_TAG        = 'P';
static const cc7::byte PD_VERSION_V2 = '3';    // SDK 0.x.x:  protocol V2
//static const cc7::byte PD_VERSION_V3 = '4';    // SDK 1.0.x:  protocol V3
static const cc7::byte PD_VERSION_V4 = '5';    // SDK 1.1.x:  + recovery codes
static const cc7::byte PD_VERSION_V5 = '6';    // SDK 1.3.x:  + signature counter byte
static const cc7::byte PD_VERSION_V6 = '7';    // SDK 2.0.x:  protocol V4


PersistentDataPtr PersistentData::deserialize(cc7::utils::DataReader& reader)
{
    auto result = reader.openVersion(PD_TAG, PD_VERSION_V2);
    if (!result) {
        throw Exception(EC_InvalidData, "Unknown persistent data format");
    }
    auto data_version = reader.currentVersion();
    if (data_version < PD_VERSION_V5) {
        // We don't support upgrade from SDK older than 1.3.x (December 2019)
        throw Exception(EC_InvalidData, "Persistent data format is too old");
    } else if (data_version > PD_VERSION_V6) {
        // Seems that newer version of SDK serialized its data. We cannot understand this format.
        throw Exception(EC_InvalidData, "Persistent data format is too new");
    }
    
    // Build data depending on serialized version
    if (data_version < PD_VERSION_V6) {
        // V3 Legacy data
        auto data = std::make_unique<V3>();
        if (!deserializeV3(reader, *data)) {
            throw Exception(EC_InvalidData, "Failed to deserialize legacy persistent data");
        }
        return std::unique_ptr<PersistentData>(new PersistentData(data, false));
        //
    } else {
        // V4 data
        auto data = std::make_unique<V4>();
        if (!deserializeV4(reader, *data)) {
            throw Exception(EC_InvalidData, "Failed to deserialize persistent data");
        }
        return std::unique_ptr<PersistentData>(new PersistentData(data, false));
        //
    }
}

void PersistentData::serialize(cc7::utils::DataWriter &writer)
{
    if (_version == Version_V4) {
        if (!validateV4(*_v4)) {
            throw Exception(EC_InternalError, "V4 data invalid before serialization");
        }
        serializeV4(writer, *_v4);
    } else {
        if (!validateV3(*_v3)) {
            throw Exception(EC_InternalError, "V3 data invalid before serialization");
        }
        serializeV3(writer, *_v3);
    }
    // clear modified flag
    _modified = false;
}

// V4 serialization

void PersistentData::serializeV4(cc7::utils::DataWriter& writer, const V4& v4) const noexcept
{
    writer.openVersion(PD_TAG, PD_VERSION_V5);
    
    // Main activation data, such as algorithm type and activation ID
    writer.writeByte    (v4.sharedSecretAlgorithm);
    writer.writeString  (v4.activationId);
    
    // Hash counter
    writer.writeByte    (v4.authCodeCounterByte);
    writer.writeData    (v4.authCodeCounterData);

    // Fctor keys
    writer.writeData    (v4.cPossessionKey);
    writer.writeData    (v4.cKnowledgeKey);
    writer.writeData    (v4.cBiometryKey);
    // additional factor related data
    writer.writeData    (v4.passwordSalt);

    // auxiliary keys
    writer.writeData    (v4.cKdkUtility);
    writer.writeData    (v4.cKdkEncryption);
    
    // public and private keys
    writer.writeData    (v4.devicePublicKey);
    writer.writeData    (v4.serverPublicKey);
    writer.writeData    (v4.cDevicePrivateKey);
    
    writer.closeVersion();
}

bool PersistentData::deserializeV4(cc7::utils::DataReader &reader, V4 &v4)
{
    bool result;
    // Main activation data, such as algorithm type and activation ID
    result =           reader.readByte      (v4.sharedSecretAlgorithm);
    result = result && reader.readString    (v4.activationId);

    // Serialize hash counter
    result = result && reader.readByte      (v4.authCodeCounterByte);
    result = result && reader.readData      (v4.authCodeCounterData);
    // Factor keys
    result = result && reader.readData      (v4.cPossessionKey);
    result = result && reader.readData      (v4.cKnowledgeKey);
    result = result && reader.readData      (v4.cBiometryKey);
    // additional factor related data
    result = result && reader.readData      (v4.passwordSalt);
    
    // auxiliary keys
    result = result && reader.readData      (v4.cKdkUtility);
    result = result && reader.readData      (v4.cKdkEncryption);
    
    // public and private keys
    result = result && reader.readData      (v4.devicePublicKey);
    result = result && reader.readData      (v4.serverPublicKey);
    result = result && reader.readData      (v4.cDevicePrivateKey);

    return result &&
            reader.closeVersion() &&
            validateV4(v4);
}

static bool _IsSet(const cc7::ByteArray & a) {
    return !a.empty();
}
static bool _IsSet(const std::string & s) {
    return !s.empty();
}
static bool _IsSet(const cc7::ByteArray & a, size_t size) {
    return a.size() == size;
}
static bool _IsEmptyOrSet(const cc7::ByteArray & a, size_t size) {
    return a.empty() || a.size() == size;
}

bool PersistentData::validateV4(const V4 &v4)
{
    auto spec = PowerAuthSpec::specForAlgorithmId(v4.sharedSecretAlgorithm);
    return
        // selected algorithm
        spec && !spec->isLegacy() &&
        _IsSet(v4.activationId) &&
        _IsSet(v4.authCodeCounterData, v4::HASH_COUNTER_SIZE) &&
        // factor keys
        _IsSet(v4.cPossessionKey, v4::UKE_PROTECTED_KEY_SIZE) &&
        _IsSet(v4.cKnowledgeKey, v4::UKE_PROTECTED_KEY_SIZE) &&
        _IsEmptyOrSet(v4.cBiometryKey, v4::UKE_PROTECTED_KEY_SIZE) &&
        _IsSet(v4.passwordSalt, v4::PASSKDF_SALT_SIZE) &&
        // auxiliary keys
        _IsSet(v4.cKdkUtility, v4::AEAD_PROTECTED_KEY_SIZE) &&
        _IsSet(v4.cKdkEncryption, v4::AEAD_PROTECTED_KEY_SIZE) &&
        // public & private keys
        _IsSet(v4.devicePublicKey) &&
        _IsSet(v4.serverPublicKey) &&
        _IsSet(v4.cDevicePrivateKey);
}

// V3 serialization

void PersistentData::serializeV3(cc7::utils::DataWriter& writer, const V3& v3) const noexcept
{
    writer.openVersion(PD_TAG, PD_VERSION_V5);
    
    // Serialize hash data or counter, depending on data version
    writer.writeData    (v3.authCodeCounterData);
    writer.writeString  (v3.activationId);
    writer.writeU32     (v3.passwordIterations);
    writer.writeData    (v3.passwordSalt);
    // write signature keys
    writer.writeData    (v3.cPossessionKey);
    writer.writeData    (v3.cKnowledgeKey);
    writer.writeData    (v3.cBiometryKey);
    writer.writeData    (v3.cTransportKey);
    // write public keys
    writer.writeData    (v3.serverPublicKey);
    writer.writeData    (v3.devicePublicKey);
    // encrypted private key
    writer.writeData    (v3.cDevicePrivateKey);
    // flags
    writer.writeU32     (v3.flagsU32);

    // encrypted recovery data (PD v4), for compatibility reason, we store
    // zero count only (e.g. no recovery data is available)
    writer.writeCount(0);
    
    // Counter byte (PD v5)
    writer.writeByte    (v3.authCodeCounterByte);
    
    writer.closeVersion();
}

bool PersistentData::deserializeV3(cc7::utils::DataReader &reader, V3 &v3)
{
    bool result;
    // Deserialize hash data or counter, depending on version stored in the header.
    result =           reader.readData      (v3.authCodeCounterData, v3::FACTOR_KEY_SIZE);
    
    result = result && reader.readString    (v3.activationId);
    result = result && reader.readU32       (v3.passwordIterations);
    result = result && reader.readData      (v3.passwordSalt, v3::PBKDF2_SALT_SIZE);
    // signature keys
    result = result && reader.readData      (v3.cPossessionKey, v3::PBKDF2_SALT_SIZE);
    result = result && reader.readData      (v3.cKnowledgeKey, v3::PBKDF2_SALT_SIZE);
    result = result && reader.readData      (v3.cBiometryKey);
    result = result && reader.readData      (v3.cTransportKey, v3::PBKDF2_SALT_SIZE);
    // public keys
    result = result && reader.readData      (v3.serverPublicKey);
    result = result && reader.readData      (v3.devicePublicKey);
    // encrypted private key
    result = result && reader.readData      (v3.cDevicePrivateKey);
    // flags
    result = result && reader.readU32       (v3.flagsU32);
    
    // encrypted recovery data (PD v4). For a compatibility reasons, we just skip possible stored bytes.
    if (reader.currentVersion() >= PD_VERSION_V4) {
        result = result && reader.skipDataOrString();
    }
    
    // signature counter byte (PD v5)
    result = result && reader.readByte(v3.authCodeCounterByte);
    
    // close versioned section & validate data
    return result &&
            reader.closeVersion() &&
            validateV3(v3);
}

bool PersistentData::validateV3(const V3 &v3)
{
    return
        // factor keys
        _IsSet(v3.cPossessionKey, v3::FACTOR_KEY_SIZE) &&
        _IsSet(v3.cKnowledgeKey, v3::FACTOR_KEY_SIZE) &&
        _IsEmptyOrSet(v3.cBiometryKey, v3::FACTOR_KEY_SIZE) &&
        // factor related data
        v3.passwordIterations >= v3::PBKDF2_PASS_ITERATIONS &&
        _IsSet(v3.passwordSalt, v3::PBKDF2_SALT_SIZE) &&
        // Activation ID
        _IsSet(v3.activationId) &&
        // Public and private keys
        _IsSet(v3.cDevicePrivateKey) &&
        _IsSet(v3.devicePublicKey) &&
        _IsSet(v3.serverPublicKey);
}

} // namespace powerAuth
