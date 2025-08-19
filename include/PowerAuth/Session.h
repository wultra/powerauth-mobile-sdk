/*
 * Copyright 2021 Wultra s.r.o.
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

#include <PowerAuth/Password.h>
#include <PowerAuth/Configuration.h>

#include <PowerAuth/TimeService.h>
#include <PowerAuth/AuthenticationService.h>
#include <PowerAuth/ByteUtils.h>
#include <PowerAuth/Debug.h>

#include <PowerAuth/Credentials.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/ActivationResult.h>
#include <PowerAuth/ActivationStatus.h>

#include <PowerAuth/PowerAuthSpec.h>
#include <PowerAuth/Algorithms.h>

namespace powerAuth {

// Forward declarations of internal classes

class Context;
class SessionData;
class IKeyProvider;

/// The `Session` object represents a client-side state machine that manages the life cycle,
/// activation process, and cryptographic operations for PowerAuth.
class Session : public std::enable_shared_from_this<Session>
{
public:
    
    // --------------------------------------------------------------------------------------------
    // Object construction
    // --------------------------------------------------------------------------------------------
    
    /// Create instance of `Session` object
    /// - Parameter configuration: Session's configuration.
    /// - Returns: smart pointer with created Session object.
    /// - Throws:
    ///      - `Exception` if object construction fails.
    static std::shared_ptr<Session> createInstance(ConfigurationPtr configuration);
    
    /// Internal session's constructor. Please use `createInstance()` method instead of direct
    /// constructor, to properly initialize the object.
    ///
    /// - Parameter context: Context object.
    Session(std::shared_ptr<Context> context);

    
    // --------------------------------------------------------------------------------------------
    // Version and state
    // --------------------------------------------------------------------------------------------
    
    /// Get protocol version at which the session currently runs.
    /// - Returns: Protocol version at which the session currently runs.
    ProtocolVersion getProtocolVersion() const noexcept;
    
    /// Get session's configuration.
    /// - Returns: Session's configuration.
    const ConfigurationPtr& getConfiguration() const noexcept;
    
    /// Load session's state from array of bytes. The method is counterpart to `saveState()`.
    /// - Parameter serialized_state: Serialized state of `Session`.
    /// - Throws:
    ///   - `Exception` in case the serialized state is invalid or not supported.
    void loadState(const cc7::ByteRange& serialized_state);
    
    /// Save session's state into sequence of bytes. The method is counterpart to `loadState()`.
    /// - Note: You can save state at any point of session's lifecycle.
    /// - Returns: Sequence of bytes with the state of the session.
    /// - Throws:
    ///   - `Exception` in case the internal data is inconsistent.
    cc7::ByteArray saveState();
    
    
    /// Get information whether internal state is modified and should be saved into the persistent
    /// storage.
    /// - Returns: `true` if state is modified and should be saved into the persistent storage.
    bool isModifiedState() const noexcept;
    
    /// Reset session's state. You should call `saveState()` after this.
    void resetState();
        
public:
    // --------------------------------------------------------------------------------------------
    // Activation
    // --------------------------------------------------------------------------------------------

    /// Get information whether the activation can be created.
    /// - Returns: `true` if activation can be created.
    bool canCreateActivation() const noexcept;
    
    /// Create PowerAuth activation.
    /// - Parameters:
    ///   - L1_data: L1 activation data.
    ///   - L2_data: L2 activation data.
    /// - Returns: Request data for create activation endpoint.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be created.
    RequestPtr createActivation(const cc7::json::JsonValue& L1_data, const cc7::json::JsonValue& L2_data);
    
    /// Confirm PowerAuth activation with initial credentials.
    /// - Parameter credentials: Initial credentials.
    /// - Returns: Request data for confirm activation endpoint. If returned pointer is `nullptr`
    ///            then the protocol doesn't support activation confirmation.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be confirmed.
    RequestPtr confirmActivation(InitialCredentialsPtr credentials);

    /// Get information whether the session has pending create activation task.
    /// To complete activation, call `confirmActivation()`.
    bool hasPendingCreateActivation() const noexcept;
    
    /// Get information whether the session contains valid activation data.
    bool hasValidActivationData() const noexcept;
    
    /// Get activation identifier.
    /// - Returns: Activation identifier or empty string if there's no activation.
    std::string activationId() const noexcept;
    
    /// Get human readable fingerprint calculated from device and server's public keys.
    /// - Returns: Human readable fingerprint calculated from device and server's public keys.
    ///            An empty string is returned in case there's no activation.
    std::string activationFingerprint() const noexcept;
    
    /// Fetch activation status.
    ///
    /// - Returns: Request data for getting activation status endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr fetchActivationStatus();
    
    /// Remove activation status.
    ///
    /// - Parameter credentials: Credentials for authentication on the server.
    /// - Returns: Request data for remove activation endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr removeActivation(const CredentialsPtr& credentials);
    
    /// Verify user's password on the server.
    /// - Parameter password: Password to verify.
    /// - Returns: Request data for verify password endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr verifyPassword(const PasswordPtr& password);
    
    /// Change user's password from old to new one.
    ///
    /// - Parameters:
    ///   - old_password: Old password.
    ///   - new_password: New password.
    /// - Returns: Request data for change password endpoint. If returned pointer is `nullptr`
    ///            then the protocol has no such endpoint defined and password is changed immediately.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr changePassword(const PasswordPtr& old_password, const PasswordPtr& new_password);
    
    
    /// Test whether session has biometric factor set.
    /// - Returns: `true` if biometric factor is set.
    /// - Throws:
    ///   - `Exception` in case of failure, for example, if there's no registration.
    bool hasBiometricFactor() const;
    
    /// Remove biometric factor.
    ///
    /// - Parameters:
    ///   - password: User's password.
    ///   - new_biometry_kek: New KEK protecting biometric factor.
    /// - Returns: Request data for remove biometric factor endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr addBiometricFactor(const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek);

    /// Remove biometric factor.
    ///
    /// - Returns: Request data for add biometric factor endpoint. If returned pointer is `nullptr`
    ///            then the protocol has no such endpoint defined and the factor is removed immediately.
    /// - Throws:
    ///   - `Exception` in case of failure.
    RequestPtr removeBiometricFactor();

private:
    
    /// Throw exception if no activation data is present.
    void checkActivationData() const;
        
public:
    // --------------------------------------------------------------------------------------------
    // Services
    // --------------------------------------------------------------------------------------------
    
    
    /// Get smart pointer with the `TimeService` object, providing time synchronization tasks.
    const TimeServicePtr& getTimeService() const noexcept;
    
    /// Get smart pointer with object implementing `IEncryptorFactory` and providing End-To-End encryption.
    const IClientEncryptorFactoryPtr& getEncryptorFactory() const noexcept;
    
    /// Get smart pointer with object implementing `IAuthenticationService`.
    const IAuthenticationServicePtr& getAuthenticationService() const noexcept;

private:
    
    SharedMutexPtr _lock;
    std::shared_ptr<Context> _context;

    /// Access the mutable session data.
    SessionData& sessionData() noexcept;
    
    /// Access the immutable session data.
    const SessionData& sessionData() const noexcept;
    
    /// Return reference to the internal key provider.
    IKeyProvider& keyProvider() noexcept;
    
    /// Return reference to object implementing `IEncryptorFactory` and providing End-To-End encryption.
    IClientEncryptorFactory& encryptorFactory() noexcept;
};

CC7_SHARED_PTR(Session)

} // namespace powerAuth
