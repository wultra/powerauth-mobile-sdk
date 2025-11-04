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

#include <PowerAuth/Request.h>
#include <PowerAuth/PowerAuthSpec.h>

namespace powerAuth {

/// The `ActivationState` defines state of local activation. Be aware that this
/// enumeration is not identical with state of activation on the server. To get
/// the exact state on the server, look for `ActivationStatus::ServerState`
/// enumeration.
enum class ActivationState
{
    /// Activation is confirmed, but awaits for commit on the server.
    PendingCommit,
    /// Activation is active and ready for operation.
    Active,
    /// Activation is blocked.
    Blocked,
    /// Activation is removed on the server.
    Removed,
    /// Activation is technically blocked, due to out-of-sync counters
    /// between client and the server.
    Deadlock
};

/// The `ActivationStatus` class contains information about activation received
/// from the server.
class ActivationStatus : public ResponseObject
{
public:
    
    enum BiometricFactor
    {
        /// Information about biometric factor is not available. Activation is still
        /// on protocol V3.
        BiometricFactor_NA = 0,
        /// Biometric factor is turned ON on the server.
        BiometricFactor_On,
        /// Biometric factor is turned OFF on the server.
        BiometricFactor_Off
    };
        
    /// The `CounterState` defines state of local counter against the server counter.
    enum CounterState
    {
        /// The state is not determined yet.
        CounterState_NA = 0,
        /// Counter is healthy, no additional action is required.
        CounterState_OK,
        /// Counter was just updated, so the session's persistent
        /// data needs to be serialized.
        CounterState_Updated,
        /// The PowerAuth symmetric signature should be calculated
        /// to prevent counter's de-synchronization.
        CounterState_CalculateAuthCode,
        /// Counter is invalid and the activation is technically blocked.
        CounterState_Invalid
    };
    
    /// The `ServerState` defines state of the activation on the server.
    /// The state is useful only for the debugging purposes.
    enum ServerState
    {
        ServerState_Created = 1,
        ServerState_PendingCommit = 2,
        ServerState_Active = 3,
        ServerState_Blocked = 4,
        ServerState_Removed = 5
    };

    /// Contains information about the protocol version.
    ProtocolVersion protocolVersion() const noexcept;

    /// Contains state of activation.
    ActivationState activationState() const noexcept;
    
    /// Contains state of activation on the server.
    ServerState serverState() const noexcept;
    
    /// Contains state of biometric factor on the server.
    BiometricFactor biometricFactor() const noexcept;

    /// Contains information whether the protocol upgrade is available for activation.
    bool isProtocolUpgradeAvailable() const noexcept;
    
    /// Contains information whether the protocol upgrade is possible. The information depends on
    /// the maximum supported protocol version configured in the SDK.
    /// - Parameter max_supported_version: Specify maximum supported version in this SDK.
    bool isProtocolUpgradePossible(ProtocolVersion max_supported_version) const noexcept;
    
    /// Contains information whether the server expects protocol upgrade confirmation.
    bool isPendingUpgradeConfirm() const noexcept;
    
    /// Contains information whether it's recommended to synchronize the local counter
    /// with the server.
    bool isCounterSynchronizationRecommended() const noexcept;
    
    /// Contains information that session's state has been changed during activation status
    /// processing and should be saved to the persistent storage.
    bool isSessionStateSerializationRecommended() const noexcept;
    
    /// Contains custom object returned from the server.
    const cc7::json::JsonValue& customObject() const noexcept;
    
    /// Contains number of failed authentication attempts.
    cc7::byte failCount() const noexcept;
    
    /// Contains maximum number of failed authentication attempts allowed on the server.
    cc7::byte maxFailCount() const noexcept;
    
    /// Contains remaining authentication attempts. The value is calculated as:
    /// ```
    /// auto remaining = maxFailCount() - failCount();
    /// ```
    cc7::byte remainingAttempts() const noexcept;
    
    
    struct BinaryData
    {
        cc7::byte state;
        cc7::byte currentVersion;
        cc7::byte upgradeVersion;
        cc7::byte failCount;
        cc7::byte maxFailCount;
        cc7::byte counterByte;
        cc7::byte lookAheadCount;
        cc7::byte statusFlags;
        cc7::ByteArray counterHash;
    };

    /// Parse binary status blob for protocol V4 and return `BinaryData` structure.
    /// - Parameter status_blob: Binary status blob.
    /// - Returns: `BinaryData` filled from status blob.
    /// - Throws: `Exception` with `EC_InvalidData` if status blob contains invalid data.
    static BinaryData parseStatusBlobV4(const cc7::ByteRange& status_blob);
    
    /// Parse binary status blob for protocol V3 and return `BinaryData` structure.
    /// - Parameter status_blob: Binary status blob.
    /// - Returns: `BinaryData` filled from status blob.
    /// - Throws: `Exception` with `EC_InvalidData` if status blob contains invalid data.
    static BinaryData parseStatusBlobV3(const cc7::ByteRange& status_blob);

    /// Construct activation status object.
    /// - Parameters:
    ///   - version: Protocol version.
    ///   - activation_state: State of activation.
    ///   - counter_state: State of counter.
    ///   - data: Parsed blob structure.
    ///   - custom_object: Custom object received together with the status blob.
    ActivationStatus(ProtocolVersion version,
                     ActivationState activation_state,
                     CounterState counter_state,
                     const BinaryData& data,
                     const cc7::json::JsonValue& custom_object);
private:
    
    /// Validate information in binary data structure for protocol V4.
    /// - Parameter data: Data to validate.
    /// - Returns: `true` if data is valid.
    static bool validateStatusBlobV4(const BinaryData& data) noexcept;
    
    /// Validate information in binary data structure for protocol V3.
    /// - Parameter data: Data to validate.
    /// - Returns: `true` if data is valid.
    static bool validateStatusBlobV3(const BinaryData& data) noexcept;
    
    ProtocolVersion _protocol_version;
    ActivationState _activation_state;
    ServerState _server_state;
    BiometricFactor _biometric_factor;
    CounterState _counter_state;
    
    cc7::byte _fail_count;
    cc7::byte _max_fail_count;
    bool _is_pending_activation_confirm;
    bool _is_pending_upgrade_confirm;
    bool _is_protocol_upgrade_available;
    
    cc7::json::JsonValue _custom_object;
};

CC7_SHARED_PTR(ActivationStatus)

} // namespace powerAuth
