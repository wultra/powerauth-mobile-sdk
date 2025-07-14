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

#include <PowerAuth/ActivationStatus.h>
#include <PowerAuth/Configuration.h>
#include "PersistentData.h"
#include "RegistrationData.h"

namespace powerAuth {

/// The `SessionData` object groups various data related to lifetime of PowerAuth activation.
class SessionData
{
public:
    
    SessionData();
    
    /// Return protocol version currently used for this instance of session data.
    ProtocolVersion getProtocolVersion() const noexcept;
    
    /// Return PowerAuth specification currently used for this instance of session data
    /// or `nullptr` if specification is not known. This is regular state of session data
    /// if there's no persistent data structure available.
    ConstPowerAuthSpecPtr getSpecification() const noexcept;
    
    /// Return `true` if session data contains persistent data (e.g. activation is created).
    bool hasPersistentData() const noexcept;
    
    /// Returns `true` if session data contains registration data (e.g. activation is in progress).
    bool hasRegistrationData() const noexcept;
    
    /// Returns `true` if session data is modified and needs to be serialized.
    bool isModified() const noexcept;
    
    /// Set new registration data.
    ///
    /// Method also removes previous instance of registration or persistent data. The method effectively
    /// sets the session into "pending activation" state.
    ///
    /// - Parameter ptr: New registration data.
    void setRegistrationData(RegistrationDataPtr& ptr);
    
    
    /// Set new persistent data
    ///
    /// Method also removes previous instance of registration or persistent data. The method effectively
    /// sets the session into "has activation" state.
    ///
    /// - Parameter ptr: New persistent data.
    void setPersistentData(PersistentDataPtr& ptr);
    
    /// Reset session data and remove any instance of registration or persistent data.
    void resetSessionData();
    
    /// Get reference to registration data.
    /// - Returns: Reference to registration data.
    /// - Throws: `Exception` with `EC_InternalError` if no registration data is set in object.
    const RegistrationData& registrationData() const;
    
    /// Get reference to registration data.
    /// - Returns: Reference to registration data.
    /// - Throws: `Exception` with `EC_InternalError` if no registration data is set in object.
    RegistrationData& registrationData();
    
    /// Get reference to persistent data.
    /// - Returns: Reference to persistent data.
    /// - Throws: `Exception` with `EC_InternalError` if no persistent data is set in object.
    const PersistentData& persistentData() const;
    
    /// Get reference to persistent data.
    /// - Returns: Reference to persistent data.
    /// - Throws: `Exception` with `EC_InternalError` if no persistent data is set in object.
    PersistentData& persistentData();
    
    /// Serialize session data.
    /// - Returns: Array of bytes with serialized state of session data.
    /// - Throws: `Exception` with `EC_InternalError` if persistent data contains invalid values.
    cc7::ByteArray serialize();
    
    /// Restore state of the object from the sequence of bytes.
    /// - Parameter serialized_data: Sequence of bytes with previous state.
    /// - Throws: `Exception` with `EC_InvalidData` if sequence of bytes contains invalid or unsupported data.
    void deserialize(const cc7::ByteRange& serialized_data);
    
    
private:
    RegistrationDataPtr _rd;
    PersistentDataPtr _pd;
    bool _modified;
};

CC7_SHARED_PTR(SessionData)

} // namespace powerAuth
