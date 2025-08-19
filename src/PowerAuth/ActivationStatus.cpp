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
    _is_protocol_upgrade_available(data.currentVersion < data.upgradeVersion),
    _is_pending_activation_confirm(data.statusFlags & STATUS_FLAG_ACTIVATION_CONFIRM),
    _is_pending_upgrade_confirm(data.statusFlags & STATUS_FLAG_UPGRADE_CONFIRM),
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

bool ActivationStatus::isProtocolUpgradeAvailable() const noexcept
{
    return _is_protocol_upgrade_available;
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
           data.currentVersion == Version_V4 &&
           data.upgradeVersion >= Version_V4 &&
           data.failCount <= data.maxFailCount &&
           data.lookAheadCount > 0 && data.lookAheadCount <= v4::LOOK_AHEAD_MAX;
}

ActivationStatus::BinaryData ActivationStatus::parseStatusBlobV3(const cc7::ByteRange& status_blob)
{
    BinaryData out {};
    ByteRange header;
    auto reader = utils::DataReader(status_blob, false);
    auto valid = reader.readMemoryRange(header, 4) &&
            reader.readByte(out.state) &&
            reader.readByte(out.currentVersion) &&
            reader.readByte(out.upgradeVersion) &&
            reader.skipBytes(5) &&  // reserved
            reader.readByte(out.counterByte) &&
            reader.readByte(out.failCount) &&
            reader.readByte(out.maxFailCount) &&
            reader.readByte(out.lookAheadCount) &&
            reader.readMemory(out.counterHash, 16) &&
            reader.remainingSize() == 0 &&
            // formal validations
            (header[0] == 0xDE && header[1] == 0xC0 && header[2] == 0xDE && header[3] == 0xD1) &&
            validateStatusBlobV3(out);
    if (!valid) {
        throw Exception(EC_InvalidData, "Invalid V3 activation status blob");
    }
    return out;
}

bool ActivationStatus::validateStatusBlobV3(const BinaryData &data) noexcept
{
    return data.state >= ServerState_Created && data.state <= ServerState_Removed &&
           data.currentVersion == Version_V3 &&
           data.upgradeVersion >= Version_V4 &&
           data.failCount <= data.maxFailCount &&
           data.lookAheadCount > 0 && data.lookAheadCount <= v3::LOOK_AHEAD_MAX;
}

} // namespace powerAuth

