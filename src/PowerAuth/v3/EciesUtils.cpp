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

#include "EciesUtils.h"

#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>
#include "../model/Constants.h"

using namespace cc7;

namespace powerAuth {
namespace v3 {

static ByteArray CalculateEnvelopeKey(const EncryptorParameters& parameters,
                                      const cc7::crypto::PrivateKey& private_key,
                                      const cc7::crypto::PublicKey& peer_key,
                                      const ByteRange& ephemeral_key_data)
{
    const auto& algs = algorithms().v3;
    auto shared_secret = algs.ecdhWithNullKdf().phase(private_key, peer_key)->getKeyData();
    // sh1 = VERSION || sharedInfo1 || ephemeralKeyData
    auto info1_data = ConcatByteRanges({
        MakeRange(v3::PA_VERSION_STRING),
        MakeRange(parameters.sharedInfo1()),
        ephemeral_key_data
    });
    return algs.kdfX963().deriveKeyBytes(shared_secret, {
        { cc7::crypto::KDF_PARAM_INFO, cc7::crypto::Parameter::ref(info1_data) },
        { cc7::crypto::KDF_PARAM_KEY_SIZE, cc7::crypto::Parameter::take((size_t)48) }
    });
}

static ByteArray CalculateSH2(const EncryptorParameters& parameters,
                              const ByteRange& transport_key)
{
    if (parameters.encryptorSpec->isApplicationScoped()) {
        // Applications scope
        return algorithms().v3.sha256().digest(MakeRange(parameters.applicationSecret));
    } else {
        // Activation scope
        if (transport_key.empty()) {
            throw Exception(EC_InternalError, "Transport key not provided for activation scoped encryptor");
        }
        if (transport_key.size() != v3::FACTOR_KEY_SIZE) {
            throw Exception(EC_InternalError, "Transport key has wrong size");
        }
        return algorithms().v3.hmacWithSha256().token(transport_key, MakeRange(parameters.applicationSecret));
    }
}

EncryptorSecretsPtr ECIES_MakeClientSecrets(const EncryptorParameters& parameters,
                                            const cc7::crypto::PublicKey& temporary_public_key,
                                            const cc7::ByteRange& transport_key)
{
    auto ephemeral_key_pair = algorithms().v3.p256().generateKeyPair();
    auto ephemeral_pub_key_data = ephemeral_key_pair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963);
    auto envelope_key = CalculateEnvelopeKey(parameters, ephemeral_key_pair->getPrivateKey(), temporary_public_key, ephemeral_pub_key_data);
    auto sh2 = CalculateSH2(parameters, transport_key);
    return EncryptorSecrets::makeSecrets(envelope_key, sh2, ephemeral_pub_key_data);
}

EncryptorSecretsPtr ECIES_TestClientSecrets(const EncryptorParameters& parameters,
                                            const cc7::ByteRange& ephemeral_public_key,
                                            const cc7::ByteRange& envelope_key,
                                            const cc7::ByteRange& transport_key)
{
    auto sh2 = CalculateSH2(parameters, transport_key);
    return EncryptorSecrets::makeSecrets(envelope_key, sh2, ephemeral_public_key);
}

//EncryptorSecretsPtr ECIES_MakeServerSecrets(const EncryptorParameters& parameters,
//                                            const cc7::crypto::PrivateKey& temporary_private_key,
//                                            const cc7::ByteRange& ephemeral_pub_key_data,
//                                            const cc7::ByteRange& transport_key)
//{
//    auto public_key = algorithms().v3.p256().newPublicKey(ephemeral_pub_key_data, cc7::crypto::KEY_FORMAT_X963);
//    auto envelope_key = CalculateEnvelopeKey(parameters, temporary_private_key, *public_key, ephemeral_pub_key_data);
//    auto sh2 = CalculateSH2(parameters, transport_key);
//    return EncryptorSecrets::makeSecrets(envelope_key, sh2, ephemeral_pub_key_data);
//}

} // namespace v3
} // namespace powerAuth
