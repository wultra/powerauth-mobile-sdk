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

namespace powerAuth {
namespace v3 {

/// Create client secrets for ECIES End-To-End encryption scheme.
/// - Parameters:
///   - parameters: Encryptor parameters.
///   - temporary_public_key: Temporary public key received from the server.
///   - transport_key: If activation scoped encryptor is being created, then this must contain value of `KEY_TRANSPORT`.
/// - Returns: `EncryptorSecrets` configured for ECIES scheme.
/// - Throws: `Exception` with `EC_InternalError` if transport key is required and is not provided.
extern EncryptorSecretsPtr ECIES_MakeClientSecrets(const EncryptorParameters& parameters,
                                                   const cc7::crypto::PublicKey& temporary_public_key,
                                                   const cc7::ByteRange& transport_key);

/// Create client secrets for testing purposes.
/// - Parameters:
///   - parameters: Encryptor parameters.
///   - ephemeral_public_key: Already created ephemeral public key.
///   - envelope_key: Already calculated envelope key.
///   - transport_key: Transport key, required for activation scoped encryptor.
extern EncryptorSecretsPtr ECIES_TestClientSecrets(const EncryptorParameters& parameters,
                                                   const cc7::ByteRange& ephemeral_public_key,
                                                   const cc7::ByteRange& envelope_key,
                                                   const cc7::ByteRange& transport_key);

} // namespace v3
} // namespace powerAuth

