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
namespace v4 {

/// Calculate authentication code used for authentication HTTP header.
/// - Parameters:
///   - factor_keys: Vector with factor keys to use for the calculation.
///   - counter: Hash based counter value.
///   - data: HTTP request body
cc7::ByteArray CalculateOnlineAuthenticationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                                const cc7::ByteRange& counter,
                                                const cc7::ByteRange& data);

/// Calculate authentication code for offline authentication purpose.
/// - Parameters:
///   - factor_keys: Vector with factor keys to use for the calculation.
///   - counter: Hash based counter value.
///   - data: Data to authenticate.
///   - component_size: Size of per-factor component in characters.
std::string CalculateOfflineAuthenticationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                              const cc7::ByteRange& counter,
                                              const cc7::ByteRange& data,
                                              size_t component_size);


} // namespace v4
} // namespace powerAuth
