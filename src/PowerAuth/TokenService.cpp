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

#include <PowerAuth/TokenService.h>

namespace powerAuth {

GetAccessTokenResponse::GetAccessTokenResponse(AuthFactors factors,
                                               const std::string_view& identifier,
                                               const cc7::ByteRange& secret) :
    _factors(factors),
    _identifier(identifier),
    _secret(secret)
{
}

AuthFactors GetAccessTokenResponse::getFactors() const noexcept
{
    return _factors;
}

const std::string& GetAccessTokenResponse::getIdentifier() const noexcept
{
    return _identifier;
}

const cc7::ByteArray& GetAccessTokenResponse::getSecret() const noexcept
{
    return _secret;
}

} // namespace powerAuth
