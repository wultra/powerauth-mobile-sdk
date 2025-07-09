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

/**
 This is a top level header. You can include this file from your project,
 whenever you need include everything from PA2 library at once.
 */

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

class Session :
    private std::enable_shared_from_this<Session>
{
public:
    
    // --------------------------------------------------------------------------------------------
    // Object construction
    //
    
    static std::shared_ptr<Session> createInstance(ConfigurationPtr configuration);
    
    // --------------------------------------------------------------------------------------------
    // Version and state
    //
    
    ProtocolVersion getProtocolVersion() const noexcept;
    const ConfigurationPtr& getConfiguration() const noexcept;
    
    void loadState(const cc7::ByteRange& serialized_state);
    cc7::ByteArray saveState() const;
    void resetState();
        
public:
    // --------------------------------------------------------------------------------------------
    // Activation
    //
    bool canCreateActivation() const noexcept;
    RequestPtr createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    RequestPtr confirmActivation(InitialCredentialsPtr credentials);
    
private:
    cc7::json::JsonValue prepareRequestActivationData(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    ResponseObjectPtr processResponseActivationData(const cc7::json::JsonValue& L1_data);
    ResponseObjectPtr processResponseActivationConfirm(InitialCredentialsPtr credentials);
    
    
public:
    // --------------------------------------------------------------------------------------------
    // Services
    //
    const TimeServicePtr& getTimeService() const noexcept;
    const IEncryptorFactoryPtr& getEncryptorFactory() const noexcept;

private:
    
    Session(std::shared_ptr<Context> context);

    SharedMutexPtr _lock;
    std::shared_ptr<Context> _context;

    SessionData& sessionData() noexcept;
    const SessionData& sessionData() const noexcept;
    
    IKeyProvider& keyProvider() noexcept;
    IEncryptorFactory& encryptorFactory() noexcept;
};

CC7_SHARED_PTR(Session)

} // namespace powerAuth
