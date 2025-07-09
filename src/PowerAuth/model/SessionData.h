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
    
    bool hasPersistentData() const noexcept;
    bool hasRegistrationData() const noexcept;
    
    bool isModified() const noexcept;
    
    void setRegistrationData(RegistrationDataPtr& ptr);
    void setPersistentData(PersistentDataPtr& ptr);
    void setActivationStatus(const ActivationStatusPtr& ptr);
    void setDeviceKey(const cc7::ByteRange& device_key);
    
    void resetSessionData();
    
    const RegistrationData& registrationData() const;
    RegistrationData& registrationData();
    
    const PersistentData& persistentData() const;
    PersistentData& persistentData();
    
    const cc7::ByteArray& deviceKey() const;
    
    const ActivationStatusPtr lastKnownActivationStatus() const;
    
    
    cc7::ByteArray serialize() const;
    void deserialize(const cc7::ByteRange& serialized_data);
    
    
private:
    RegistrationDataPtr _rd;
    PersistentDataPtr _pd;
};

CC7_SHARED_PTR(SessionData)

} // namespace powerAuth
