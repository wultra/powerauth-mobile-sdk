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

#include <PowerAuth/Service.h>
#include <PowerAuth/Credentials.h>
#include <PowerAuth/Request.h>
#include <PowerAuth/ActivationResult.h>
#include <PowerAuth/ActivationStatus.h>

namespace powerAuth {

/// The `IActivationService` defines interface for activation related tasks.
class IActivationService {
public:
    virtual ~IActivationService() = default;
    
    /// Return instance of this object implementing `IService` interface.
    virtual IServicePtr asService() = 0;
    
    /// Return protocol version supported by the instance of the object.
    virtual ProtocolVersion protocolVersion() const noexcept = 0;
        
    /// Create PowerAuth activation. In case of success, the `ActivationResult` object
    /// is created in the response processing.
    ///
    /// - Parameters:
    ///   - L1_data: L1 activation data.
    ///   - L2_data: L2 activation data.
    /// - Returns: Request data for create activation endpoint.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be created.
    virtual RequestPtr createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data) = 0;
    
    /// Confirm PowerAuth activation with initial credentials.
    ///
    /// - Parameter credentials: Initial credentials.
    /// - Returns: Request data for confirm activation endpoint. If returned pointer is `nullptr`
    ///            then the protocol has no such endpoint defined and activation is confirmed immediately.
    /// - Throws:
    ///   - `Exception` in case that activation cannot be confirmed.
    virtual RequestPtr confirmActivation(InitialCredentialsPtr credentials) = 0;
    
    /// Calculate human readable fingerprint from device's and server's public keys.
    ///
    /// - Returns: Human readable fingerprint calculated from device and server's public keys.
    /// - Throws:
    ///   - `Exception` in case that activation is in wrong state.
    virtual std::string calculateActivationFingerprint() = 0;
    
    /// Reset underlying session's state.
    virtual void resetState() = 0;

    /// Fetch activation status.
    ///
    /// - Returns: Request data for getting activation status endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr fetchActivationStatus() = 0;

    /// Remove activation status.
    ///
    /// - Parameter credentials: Credentials for authentication on the server.
    /// - Returns: Request data for remove activation endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr removeActivation(CredentialsPtr credentials) = 0;
    
    /// Change user's password from old to new one.
    ///
    /// - Parameters:
    ///   - old_password: Old password.
    ///   - new_password: New password.
    /// - Returns: Request data for change password endpoint. If returned pointer is `nullptr`
    ///            then the protocol has no such endpoint defined and password is changed immediately.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr changePassword(PasswordPtr old_password, PasswordPtr new_password) = 0;
    
    /// Remove biometric factor.
    ///
    /// - Parameters:
    ///   - password: User's password.
    ///   -
    /// - Returns: Request data for remove biometric factor endpoint.
    /// - Throws:
    ///   - `Exception` in case of failure.

    virtual RequestPtr addBiometricFactor(PasswordPtr password, const cc7::ByteRange& new_biometry_kek) = 0;

    /// Remove biometric factor.
    ///
    /// - Returns: Request data for add biometric factor endpoint. If returned pointer is `nullptr`
    ///            then the protocol has no such endpoint defined and the factor is removed immediately.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr removeBiometricFactor() = 0;
};

CC7_SHARED_PTR(IActivationService)

} // namespace powerAuth
