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

#include <PowerAuth/ActivationStatus.h>
#include <cc7/utils/DataReader.h>
#include "model/Constants.h"

using namespace cc7;

namespace powerAuth {

namespace {

void requireStatusBlobRead(bool ok, const char* field, const utils::DataReader& reader, const ByteRange& status_blob)
{
    if (ok) {
        return;
    }
    CC7_LOG("parseStatusBlobV3: failed to read %s, offset=%zu remaining=%zu blobSize=%zu blob=%s",
            field,
            reader.currentOffset(),
            reader.remainingSize(),
            status_blob.size(),
            status_blob.hexString().c_str());
    throw Exception(EC_InvalidData, std::string("Invalid V3 activation status blob: ") + field);
}

} // namespace

// MARK: - Construction

#define STATUS_FLAG_ACTIVATION_CONFIRM    (1 << 0)
#define STATUS_FLAG_UPGRADE_CONFIRM       (1 << 1)
#define STATUS_FLAG_UNSUPPORTED_ALGORITHM (1 << 2)  // reserved for future use
#define STATUS_FLAG_BIOMETRY_FACTOR_ON    (1 << 3)

ActivationStatus::ActivationStatus(ProtocolVersion version,
                                   ActivationState activation_state,
                                   CounterState counter_state,
                                   const BinaryData& data,
                                   const cc7::json::JsonValue& custom_object) :
    _protocol_version(version),
    _activation_state(activation_state),
    _counter_state(counter_state),
    _server_state(static_cast<ActivationStatus::ServerState>(data.state)),
    _fail_count(data.failCount),
    _max_fail_count(data.maxFailCount),
    _upgrade_version(data.upgradeVersion),
    _is_pending_activation_confirm(data.statusFlags & STATUS_FLAG_ACTIVATION_CONFIRM),
    _is_unsupported_algorithm(data.statusFlags & STATUS_FLAG_UNSUPPORTED_ALGORITHM),
    _is_protocol_upgrade_available(data.currentVersion < data.upgradeVersion),
    _is_pending_upgrade_confirm(data.statusFlags & STATUS_FLAG_UPGRADE_CONFIRM),
    _is_remove_biometric_kek_recommended(false),
    _custom_object(custom_object)
{
    bool is_valid;
    if (version >= Version_V4) {
        is_valid = validateStatusBlobV4(data);
        _biometric_factor = (data.statusFlags & STATUS_FLAG_BIOMETRY_FACTOR_ON) ? BiometricFactor_On : BiometricFactor_Off;
    } else {
        is_valid = validateStatusBlobV3(data);
        _biometric_factor = BiometricFactor_NA;
    }
    if (!is_valid) {
        throw Exception(EC_InternalError, "Invalid binary status blob data");
    }
}

// MARK: - Getters

ActivationState ActivationStatus::activationState() const noexcept
{
    return _activation_state;
}

ActivationStatus::ServerState ActivationStatus::serverState() const noexcept
{
    return _server_state;
}

ActivationStatus::BiometricFactor ActivationStatus::biometricFactor() const noexcept
{
    return _biometric_factor;
}

bool ActivationStatus::isPendingActivationConfirm() const noexcept
{
    return _is_pending_activation_confirm;
}

bool ActivationStatus::isUnsupportedAlgorithm() const noexcept
{
    return _is_unsupported_algorithm;
}

bool ActivationStatus::isProtocolUpgradeAvailable() const noexcept
{
    return _is_protocol_upgrade_available;
}

bool ActivationStatus::isProtocolUpgradePossible(ProtocolVersion current_version, ProtocolVersion max_supported_version) const noexcept
{
    return _upgrade_version > current_version
        && _upgrade_version <= max_supported_version;
}

bool ActivationStatus::isPendingUpgradeConfirm() const noexcept
{
    return _is_pending_upgrade_confirm;
}

bool ActivationStatus::isCounterSynchronizationRecommended() const noexcept
{
    if (_activation_state == ActivationState::Active) {
        return _counter_state == CounterState_CalculateAuthCode;
    }
    return false;
}

bool ActivationStatus::isSessionStateSerializationRecommended() const noexcept
{
    return _counter_state == CounterState_Updated;
}

bool ActivationStatus::isRemoveBiometricKekRecommended() const noexcept
{
    return _is_remove_biometric_kek_recommended;
}

void ActivationStatus::setRemoveBiometricKekRecommended() noexcept
{
    _is_remove_biometric_kek_recommended = true;
}

ProtocolVersion ActivationStatus::protocolVersion() const noexcept
{
    return _protocol_version;
}

const cc7::json::JsonValue& ActivationStatus::customObject() const noexcept
{
    return _custom_object;
}

cc7::byte ActivationStatus::failCount() const noexcept
{
    return _fail_count;
}

cc7::byte ActivationStatus::maxFailCount() const noexcept
{
    return _max_fail_count;
}

cc7::byte ActivationStatus::remainingAttempts() const noexcept
{
    if (_activation_state == ActivationState::Active) {
        return _max_fail_count - _fail_count;
    }
    return 0;
}

// MARK: - Parse

ActivationStatus::BinaryData ActivationStatus::parseStatusBlobV4(const cc7::ByteRange& status_blob)
{
    BinaryData out {};
    ByteRange header;
    auto reader = utils::DataReader(status_blob, false);
    auto valid = reader.readMemoryRange(header, 4) &&
            reader.readByte(out.state) &&
            reader.readByte(out.currentVersion) &&
            reader.readByte(out.upgradeVersion) &&
            reader.readByte(out.statusFlags) &&
            reader.skipBytes(4) &&  // reserved
            reader.readByte(out.counterByte) &&
            reader.readByte(out.failCount) &&
            reader.readByte(out.maxFailCount) &&
            reader.readByte(out.lookAheadCount) &&
            reader.readMemory(out.counterHash, 32) &&
            // formal validations
            (header[0] == 0xDE && header[1] == 0xC0 && header[2] == 0xDE && header[3] == 0xD4) &&
            validateStatusBlobV4(out);
    if (!valid) {
        throw Exception(EC_InvalidData, "Invalid V4 activation status blob");
    }
    return out;
}

bool ActivationStatus::validateStatusBlobV4(const BinaryData &data) noexcept
{
    return data.state >= ServerState_Created && data.state <= ServerState_Removed &&
           (data.currentVersion == Version_V4 ||
            (data.currentVersion == Version_V3 && data.statusFlags & STATUS_FLAG_UPGRADE_CONFIRM)
           ) &&
           data.upgradeVersion >= Version_V4 &&
           data.failCount <= data.maxFailCount &&
           data.lookAheadCount > 0 && data.lookAheadCount <= v4::LOOK_AHEAD_MAX;
}

ActivationStatus::BinaryData ActivationStatus::parseStatusBlobV3(const cc7::ByteRange& status_blob)
{
    BinaryData out {};
    ByteRange header;
    auto reader = utils::DataReader(status_blob, false);
    requireStatusBlobRead(reader.readMemoryRange(header, 4), "header", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.state), "state", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.currentVersion), "currentVersion", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.upgradeVersion), "upgradeVersion", reader, status_blob);
    requireStatusBlobRead(reader.skipBytes(5), "reserved", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.counterByte), "counterByte", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.failCount), "failCount", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.maxFailCount), "maxFailCount", reader, status_blob);
    requireStatusBlobRead(reader.readByte(out.lookAheadCount), "lookAheadCount", reader, status_blob);
    requireStatusBlobRead(reader.readMemory(out.counterHash, 16), "counterHash", reader, status_blob);
    if (reader.remainingSize() != 0) {
        CC7_LOG("parseStatusBlobV3: unexpected trailing bytes, remaining=%zu blobSize=%zu blob=%s",
                reader.remainingSize(),
                status_blob.size(),
                status_blob.hexString().c_str());
        throw Exception(EC_InvalidData, "Invalid V3 activation status blob: trailing bytes");
    }
    if (!(header.size() == 4 && header[0] == 0xDE && header[1] == 0xC0 && header[2] == 0xDE && header[3] == 0xD1)) {
        CC7_LOG("parseStatusBlobV3: invalid header %02X%02X%02X%02X blob=%s",
                header.size() > 0 ? header[0] : 0,
                header.size() > 1 ? header[1] : 0,
                header.size() > 2 ? header[2] : 0,
                header.size() > 3 ? header[3] : 0,
                status_blob.hexString().c_str());
        throw Exception(EC_InvalidData, "Invalid V3 activation status blob: header magic");
    }
    if (!validateStatusBlobV3(out)) {
        throw Exception(EC_InvalidData, "Invalid V3 activation status blob: validation");
    }
    return out;
}

bool ActivationStatus::validateStatusBlobV3(const BinaryData &data) noexcept
{
    if (data.state < ServerState_Created || data.state > ServerState_Removed) {
        CC7_LOG("validateStatusBlobV3: invalid state=%u (expected %u..%u)",
                static_cast<unsigned>(data.state),
                static_cast<unsigned>(ServerState_Created),
                static_cast<unsigned>(ServerState_Removed));
        return false;
    }
    if (data.currentVersion != Version_V3) {
        CC7_LOG("validateStatusBlobV3: invalid currentVersion=%u (expected %u)",
                static_cast<unsigned>(data.currentVersion),
                static_cast<unsigned>(Version_V3));
        return false;
    }
    if (data.upgradeVersion < Version_V3) {
        CC7_LOG("validateStatusBlobV3: invalid upgradeVersion=%u (expected >= %u)",
                static_cast<unsigned>(data.upgradeVersion),
                static_cast<unsigned>(Version_V3));
        return false;
    }
    if (data.failCount > data.maxFailCount) {
        CC7_LOG("validateStatusBlobV3: failCount=%u > maxFailCount=%u",
                static_cast<unsigned>(data.failCount),
                static_cast<unsigned>(data.maxFailCount));
        return false;
    }
    if (data.lookAheadCount == 0 || data.lookAheadCount > v3::LOOK_AHEAD_MAX) {
        CC7_LOG("validateStatusBlobV3: invalid lookAheadCount=%u (expected 1..%zu)",
                static_cast<unsigned>(data.lookAheadCount),
                v3::LOOK_AHEAD_MAX);
        return false;
    }
    return true;
}

} // namespace powerAuth

