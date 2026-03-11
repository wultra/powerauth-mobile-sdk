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

#include <PowerAuth/Service.h>
#include <PowerAuth/Debug.h>
#include "Context.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

Service::Service(const std::string& service_name, const SharedMutexPtr& shared_mutex) noexcept :
    _service_name(service_name),
    _lock(shared_mutex == nullptr ? std::make_shared<SharedMutex>() : shared_mutex),
    _is_destroyed(false)
{
    CC7_LOG("%s: service created", _service_name.c_str());
}

const std::string& Service::serviceName() const noexcept
{
    return _service_name;
}

// MARK: - Destroy

bool Service::isServiceDestroyed() const noexcept
{
    LOCK_GUARD();
    return _is_destroyed || _in_destroy;
}

void Service::destroyService()
{
    LOCK_GUARD();
    if (!_is_destroyed && !_in_destroy) {
        _in_destroy = true;
        doServiceDestroy();
        _in_destroy = false;
        _is_destroyed = true;
    }
}

void Service::checkNotDestroyed() const
{
    if (_is_destroyed) {
        throw Exception(EC_InternalError, "Service `" + _service_name + "` instance is already destroyed");
    }
}

void Service::doServiceDestroy()
{
    CC7_LOG("%s: service destroyed", _service_name.c_str());
}

// MARK: - Sensitive data

void Service::clearSensitiveData()
{
    checkNotDestroyed();
    CC7_LOG("%s: sensitive data cleanup", _service_name.c_str());
}

void Service::restoreSensitiveData()
{
    checkNotDestroyed();
    CC7_LOG("%s: sensitive data restore", _service_name.c_str());
}

void Service::clearActivationData()
{
    checkNotDestroyed();
    CC7_LOG("%s: activation data clear", _service_name.c_str());
}

// MARK: - Service with context

ServiceWithContext::ServiceWithContext(const std::string& service_name,
                                       const std::shared_ptr<Context>& context,
                                       const SharedMutexPtr& shared_mutex) noexcept :
    Service(service_name, shared_mutex != nullptr ? shared_mutex : context->getSharedMutexPtr()),
    _weak_context(context)
{
}

std::shared_ptr<Context> ServiceWithContext::lockContext() const
{
    if (auto context = _weak_context.lock()) {
        return context;
    }
    throw Exception(EC_InternalError, "Context is no longer available in service " + _service_name);
}

} // namespace powerAuth
