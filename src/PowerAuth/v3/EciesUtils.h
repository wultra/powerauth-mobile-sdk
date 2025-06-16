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

extern EncryptorSecretsPtr ECIES_MakeClientSecrets(const EncryptorParameters& parameters,
                                                   const cc7::crypto::PublicKey& temporary_public_key,
                                                   const cc7::ByteRange& transport_key);

extern EncryptorSecretsPtr ECIES_TestClientSecrets(const EncryptorParameters& parameters,
                                                   const cc7::ByteRange& ephemeral_public_key,
                                                   const cc7::ByteRange& envelope_key,
                                                   const cc7::ByteRange& transport_key);

extern EncryptorSecretsPtr ECIES_MakeServerSecrets(const EncryptorParameters& parameters,
                                                   const cc7::crypto::PrivateKey& temporary_private_key,
                                                   const cc7::ByteRange& ephemeral_pub_key_data,
                                                   const cc7::ByteRange& transport_key);

} // namespace v3
} // namespace powerAuth

