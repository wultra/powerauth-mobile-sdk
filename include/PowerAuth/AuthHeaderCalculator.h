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
#include <PowerAuth/Credentials.h>

namespace powerAuth {

struct AuthHeaderRequestData
{
    std::string_view httpMethod;
    std::string_view uriIdentifier;
    cc7::ByteRange body;
};

struct OfflineCodeRequestData
{
    std::string_view uriIdentifier;
    cc7::ByteRange body;
    std::string_view offlineNonce;
    size_t offlineSignatureLength = 8;
};

class IAuthHeaderCalculator
{
public:
    virtual ~IAuthHeaderCalculator() = default;
    
    virtual HttpHeader calculateOnlineAuthenticationHeader(const Credentials& auth, const AuthHeaderRequestData& request) = 0;
    virtual std::string calculateOfflineAuthenticationCode(const Credentials& auth, const OfflineCodeRequestData& request) = 0;
};

typedef std::shared_ptr<IAuthHeaderCalculator> IAuthHeaderCalculatorPtr;

} // namespace powerAuth
