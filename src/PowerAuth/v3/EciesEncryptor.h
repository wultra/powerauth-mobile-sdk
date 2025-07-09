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

#include <PowerAuth/Encryptor.h>
#include <PowerAuth/TimeService.h>

#include "EciesUtils.h"

namespace powerAuth {
namespace v3 {

class EciesClientEncryptor : public IClientEncryptor
{
public:
    EciesClientEncryptor(EncryptorParametersPtr& parameters,
                         EncryptorSecretsPtr& secrets,
                         const TimeServicePtr& time_service);
    
    EciesClientEncryptor(EncryptorParametersPtr& parameters,
                         EncryptorSecretsPtr& secrets,
                         const cc7::ByteRange& nonce,
                         const TimeServicePtr& time_service);

    bool canEncryptRequest() const noexcept override;
    bool canDecryptResponse() const noexcept override;
    EncryptedRequest encryptRequest(const cc7::ByteRange &data) override;
    cc7::ByteArray decryptResponse(const EncryptedResponse &response) override;

    /// Relax time synchronization validation for test purposes. The method does nothing
    /// in release build of the library.
    void disableFailWhenTimeIsNotSynchronized();

private:
    const EncryptorParametersPtr _parameters;
    const EncryptorSecretsPtr _secrets;
    const TimeServicePtr _time_service;
    const cc7::ByteArray _request_nonce;

    bool _fail_on_nosync_time;
    
    TimeService::TaskId _time_sync_task;
    
    cc7::ByteArray getAAD(Timestamp timestamp, const cc7::ByteRange& nonce, const cc7::ByteRange& ephemeral_key) const;
};

} // namespace v3
} //namespace powerAuth
