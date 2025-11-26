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

#include <cc7/crypto/Crypto.h>

namespace powerAuth {
namespace common {

/// Determine whether provided key is EC key.
/// - Parameter key: Key to test.
bool IsEcKey(const cc7::crypto::Key& key) noexcept;

/// Function exports key to normalized form. The method is useful for various fingerprint calculations.
/// - Parameter public_key: Public key.
cc7::ByteArray ExportKeyToNormalizedForm(const cc7::crypto::PublicKey& public_key);

/// Calculate human readable code from given hash.
/// - Parameters:
///   - hash: Input hash.
///   - code_size: Expected size of code.
/// - Throws:
///   - `Exception` with `EC_WrongParam` in case that `hash` is too short, or `code_size` is out of range.
std::string CalculateHumanReadableCodeFromHash(const cc7::ByteRange& hash, size_t code_size);

/// Normalize data for authentication code or header calculation.
/// - Parameters:
///   - method: HTTP method (use POST for offline code)
///   - uri: URI identifier.
///   - nonce_b64: Nonce in Base64 format.
///   - body: Request body.
///   - app_secret: Application secret.
cc7::ByteArray NormalizeDataForAuthCodeCalculation(const std::string_view & method,
                                                   const std::string_view & uri,
                                                   const std::string_view & nonce_b64,
                                                   const cc7::ByteRange & body,
                                                   const std::string_view & app_secret);

/// Function calculates distance between server and client counter. Each counter is represented
/// as least significant byte from the counter.
/// - Parameters:
///   - local_ctr: Local counter.
///   - server_ctr: Counter received from the server.
/// - Returns: Absolute distance between the counters.
int CalculateDistanceBetweenByteCounters(cc7::byte local_ctr, cc7::byte server_ctr);

} // namespace common
} // namespace powerAuth
