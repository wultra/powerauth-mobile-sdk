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

namespace powerAuth {

/// The `IService` provides basic interface for service based classes.
class IService
{
public:
    virtual ~IService() = default;
    
    /// Contains `true` if service is already destroyed.
    virtual bool isServiceDestroyed() const noexcept = 0;

    /// Set service as destroyed. The destroyed service should
    /// no longer perform any operations after this call.
    virtual void destroyService() = 0;
    
    /// The service's implementation should erase all sensitive data stored in memory.
    ///
    /// The method is typically called when application is going to background.
    virtual void clearSensitiveData() = 0;
    
    /// The service's implementation should erase all activation related data.
    ///
    /// The method should be called on activation remove.
    virtual void clearActivationData() = 0;
    
    /// The service's implementation may restore (if possible) sensitive data previously
    /// cleared in `clearSensitiveData()`.
    ///
    /// The method is typically called when application is going to foreground.
    virtual void restoreSensitiveData() = 0;
};

CC7_SHARED_PTR(IService)

/// The `Service` class provides default `IService` implementation.
class Service :
    public IService
{
public:
    /// Construct service with its name. The name is useful only for the debugging
    /// purposes.
    /// - Parameters:
    ///   - service_name: Service's name.
    ///   - shared_mutex: Pointer to shared mutex. If `nullptr` is provided, then the
    ///                   service creates its own mutex internally.
    Service(const std::string& service_name,
            const SharedMutexPtr& shared_mutex = nullptr) noexcept;
    
    /// Contains service's name.
    const std::string& serviceName() const noexcept;
    
    void destroyService() override;
    void clearSensitiveData() override;
    void clearActivationData() override;
    void restoreSensitiveData() override;
    bool isServiceDestroyed() const noexcept override;
    
protected:

    /// The service should override this method and implement its own destroy method.
    ///
    /// The method is called only once during the lifetime of the service.
    /// The default implementation only prints information message to the debug log.
    virtual void doServiceDestroy();
    
    /// Check whether service is not destroyed. If the service is already destroyed,
    /// then throws `Exception` with `EC_InternalError` code.
    void checkNotDestroyed() const;
    
    /// Contains name of the service.
    const std::string _service_name;
    
    /// Shared lock object.
    const SharedMutexPtr _lock;
    
private:

    /// Indicate whether service is destroyed.
    bool _is_destroyed;
    /// Service is in process of destroy.
    bool _in_destroy;
};


/// The `ServiceWithContext` extends base `Service` with ability to keep weak pointer
/// to `Context` object.
class ServiceWithContext : public Service
{
public:
    /// Construct service with its name and capture weak pointer to `Context`.
    /// purposes.
    /// - Parameters:
    ///   - service_name: Service's name.
    ///   - context: Pointer to `Context` object.
    ///   - shared_mutex: Pointer to shared mutex. If `nullptr` is provided, then the
    ///                   service use shared mutex from the `Context` object.
    ServiceWithContext(const std::string& service_name,
                       const std::shared_ptr<Context>& context,
                       const SharedMutexPtr& shared_mutex = nullptr) noexcept;
protected:
    
    /// Acquire context from weak pointer. If context is no longer available,
    /// then function throws internal error.
    std::shared_ptr<Context> lockContext() const;
    
private:
    std::weak_ptr<Context> _weak_context;
};

} // namespace powerAuth
