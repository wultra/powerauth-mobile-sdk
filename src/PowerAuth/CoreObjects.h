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

#include <PowerAuth/Types.h>
#include <PowerAuth/Configuration.h>
#include <PowerAuth/TimeService.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/KeyProvider.h>
#include <PowerAuth/SharedSecret.h>
#include <PowerAuth/PowerAuthSpec.h>

namespace powerAuth {

class CoreObjects {
public:
    
    const Configuration& configuration() const;

    TimeService& timeService();
    IEncryptorFactory& encryptorFactory();
    ISharedSecret& sharedSecret();

    
    const SharedMutexPtr getSharedMutexPtr() const noexcept;
    const ConfigurationPtr& getConfigurationPtr() const noexcept;
    const TimeServicePtr& getTimeServicePtr() const noexcept;
    const IEncryptorFactoryPtr& getEncryptorFactoryPtr() const noexcept;
    const ISharedSecretPtr& getSharedSecretPtr() const noexcept;
    
    static std::shared_ptr<CoreObjects> getInstance(ConfigurationPtr configuration, ProtocolVersion version);
    
private:
    const ConfigurationPtr _configuration;
    
    SharedMutexPtr _shared_mutex;
    TimeServicePtr _time_service;
    IEncryptorFactoryPtr _encryptor_factory;
    ISharedSecretPtr _shared_secret;
};

typedef std::shared_ptr<CoreObjects> CoreObjectsPtr;

} // namespace powerAuth

