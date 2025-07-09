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
#include <PowerAuth/ByteUtils.h>
#include <PowerAuth/Debug.h>

#include <PowerAuth/Credentials.h>
#include <PowerAuth/Encryptor.h>
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
    cc7::ByteArray saveState() const;
    
    
    /// Get information whether internal state is modified and should be saved into the persistent
    /// storage.
    /// - Returns: `true` if state is modified and should be saved into the persistent storage.
    bool isModifiedState() const noexcept;
    
    /// Reset session's state. You should call `saveState()`
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
    RequestPtr createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    
    /// Confirm PowerAuth activation with initial credentials.
    /// - Parameter credentials: Initial credentials.
    /// - Returns: Request data for confirm activation endpoint.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be confirmed.
    RequestPtr confirmActivation(InitialCredentialsPtr credentials);
    
    /// Get information whether the session contains valid activation data.
    bool hasValidActivationData() const noexcept;
    
    /// Get activation identifier.
    /// - Returns: Activation identifier or empty string if there's no activation.
    std::string activationId() const noexcept;

private:
    
    /// The method prepares activation data and creates L1 request body for the activation creation endpoint.
    ///
    /// The returned body contains encrypted L2 activation data and original L1 data provided at input.
    ///
    /// - Parameters:
    ///   - L1_data: L1 activation data.
    ///   - L2_data: L2 activation data.
    /// - Returns: Request body for confirm activation endpoint.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be created.
    cc7::json::JsonValue prepareRequestActivationData(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    
    /// The method processes response from the activation create endpoint, received from the server.
    /// - Parameter L1_data: L1 activation response.
    /// - Returns: `nullptr` in the current implementation.
    /// - Throws:
    ///   - `Exception` in case that response is invalid, or the session is no longer in .
    ResponseObjectPtr processResponseActivationData(const cc7::json::JsonValue& L1_data);

    /// The method complete the activation after successful response is received from the confirm activation endpoint.
    /// - Parameter credentials: Initial user's credentials.
    /// - Returns: `nullptr` in the current implementation.
    ResponseObjectPtr processResponseActivationConfirm(InitialCredentialsPtr credentials);
    
    
public:
    // --------------------------------------------------------------------------------------------
    // Services
    // --------------------------------------------------------------------------------------------
    
    
    /// Get smart pointer with the `TimeService` object, providing time synchronization tasks.
    const TimeServicePtr& getTimeService() const noexcept;
    
    /// Get smart pointer with object implementing `IEncryptorFactory` and providing End-To-End encryption.
    const IClientEncryptorFactoryPtr& getEncryptorFactory() const noexcept;

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
