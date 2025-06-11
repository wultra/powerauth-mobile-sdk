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

#include "CoreObjects.h"

namespace powerAuth {

// MARK: - CoreObjectsRegistry

const Configuration& CoreObjects::configuration() const
{
    return *_configuration;
}

TimeService& CoreObjects::timeService()
{
    return *_time_service;
}

IEncryptorFactory& CoreObjects::encryptorFactory()
{
    return *_encryptor_factory;
}

ISharedSecret& CoreObjects::sharedSecret()
{
    return *_shared_secret;
}

IHttpHeaderBuilder& CoreObjects::headerBuilder()
{
    return *_header_builder;
}

const SharedMutexPtr CoreObjects::getSharedMutexPtr() const noexcept
{
    return _shared_mutex;
}

const ConfigurationPtr& CoreObjects::getConfigurationPtr() const noexcept
{
    return _configuration;
}

const TimeServicePtr& CoreObjects::getTimeServicePtr() const noexcept
{
    return _time_service;
}

const IEncryptorFactoryPtr& CoreObjects::getEncryptorFactoryPtr() const noexcept
{
    return _encryptor_factory;
}

const ISharedSecretPtr& CoreObjects::getSharedSecretPtr() const noexcept
{
    return _shared_secret;
}

const IHttpHeaderBuilderPtr& CoreObjects::getHeaderBuilderPtr() const noexcept
{
    return _header_builder;
}



// MARK: - PowerAuthEngine

} // namespace powerAuth
