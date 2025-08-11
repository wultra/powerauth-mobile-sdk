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

#include "RegistrationData.h"

namespace powerAuth {

RegistrationDataPtr RegistrationData::create(ProtocolVersion version)
{
    return std::unique_ptr<RegistrationData>(new RegistrationData(version));
}

RegistrationData::RegistrationData(ProtocolVersion version) :
    _version(version),
    _v3(std::unique_ptr<V3>(version == Version_V3 ? new V3() : nullptr)),
    _v4(std::unique_ptr<V4>(version == Version_V4 ? new V4() : nullptr))
{
}

RegistrationData::V4& RegistrationData::v4()
{
    if (_v4) {
        return *_v4;
    }
    throw Exception(EC_NotAllowed, "V4 data not available");
}

const RegistrationData::V4& RegistrationData::v4() const
{
    if (_v4) {
        return *_v4;
    }
    throw Exception(EC_NotAllowed, "V4 data not available");
}

RegistrationData::V3& RegistrationData::v3()
{
    if (_v3) {
        return *_v3;
    }
    throw Exception(EC_NotAllowed, "V3 data not available");
}

const RegistrationData::V3& RegistrationData::v3() const
{
    if (_v3) {
        return *_v3;
    }
    throw Exception(EC_NotAllowed, "V3 data not available");
}

std::string RegistrationData::getActivationId() const
{
    auto activation_id = _version == Version_V4 ? _v4->activationId : _v3->activationId;
    if (activation_id.empty()) {
        throw Exception(EC_MissingActivation, "Activation ID is not available yet");
    }
    return activation_id;
}

bool RegistrationData::isKeyExchangeComplete() const noexcept
{
    auto activation_id = _version == Version_V4 ? _v4->activationId : _v3->activationId;
    return !activation_id.empty();
}

} // namespace powerAuth
