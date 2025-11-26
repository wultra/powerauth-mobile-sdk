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

#include <PowerAuth/ECIES.h>
#include <PowerAuth/ByteUtils.h>
#include <PowerAuth/Algorithms.h>
#include <cc7/Endian.h>
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"

namespace powerAuth {
// ----------------------------------------------------------------------------------------------
// MARK: - Envelope key -
//
ECIESEnvelopeKey::ECIESEnvelopeKey(const cc7::ByteRange & range) :
_key(range)
{
}

ECIESEnvelopeKey& ECIESEnvelopeKey::operator=(const cc7::ByteRange & range)
{
    _key.assign(range);
    return *this;
}

bool ECIESEnvelopeKey::isValid() const
{
    return _key.size() == EnvelopeKeySize;
}

void ECIESEnvelopeKey::invalidate()
{
    _key.secureClear();
}

const cc7::ByteRange ECIESEnvelopeKey::encKey() const
{
    if (isValid()) {
        return _key.byteRange().subRange(EncKeyOffset, EncKeySize);
    }
    return cc7::ByteRange();
}

const cc7::ByteRange ECIESEnvelopeKey::macKey() const
{
    if (isValid()) {
        return _key.byteRange().subRange(MacKeyOffset, MacKeySize);
    }
    return cc7::ByteRange();
}

const cc7::ByteRange ECIESEnvelopeKey::ivKey() const
{
    if (isValid()) {
        return _key.byteRange().subRange(IvKeyOffset, IvKeySize);
    }
    return cc7::ByteRange();
}

const cc7::ByteRange ECIESEnvelopeKey::rawKeyBytes() const
{
    return _key.byteRange();
}

cc7::ByteArray ECIESEnvelopeKey::deriveIvForNonce(const cc7::ByteRange & nonce) const
{
    return protocol::DeriveSecretKeyFromIndex(ivKey(), nonce);
}

ECIESEnvelopeKey ECIESEnvelopeKey::fromPublicKey(const cc7::crypto::PublicKeyPtr & public_key, const cc7::ByteRange & shared_info1, cc7::ByteArray & out_ephemeral_key)
{
    ECIESEnvelopeKey ek;
    // Generate ephemeral key pair
    auto ephemeral = algorithms().v3.p256().generateKeyPair();
    // Compute shared secret
    auto shared_secret = algorithms().v3.ecdhWithNullKdf().phase(ephemeral->getPrivateKey(), *public_key);
    out_ephemeral_key = ephemeral->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963);
    // Concat shared_info1 + ephemeral key.
    cc7::ByteArray info1_data = utils::ByteUtils_Concat({ cc7::MakeRange(protocol::PA_VERSION_V3), shared_info1, out_ephemeral_key});
    ek._key = algorithms().v3.kdfX963().deriveKeyBytes(shared_secret->getKeyData(), {
        { cc7::crypto::KDF_PARAM_INFO,     cc7::crypto::Parameter::ref(info1_data) }
    });
    return ek;
}

ECIESEnvelopeKey ECIESEnvelopeKey::fromPrivateKey(const cc7::crypto::PrivateKeyPtr & private_key, const cc7::ByteRange & ephemeral_key, const cc7::ByteRange & shared_info1)
{
    ECIESEnvelopeKey ek;
    // Import ephemeral public key
    auto ephemeral = algorithms().v3.p256().newPublicKey(ephemeral_key, cc7::crypto::KEY_FORMAT_RAW);
    // Compute shared secret
    auto shared_secret = algorithms().v3.ecdhWithNullKdf().phase(*private_key, *ephemeral);
    // Concat shared_info1 + ephemeral key.
    cc7::ByteArray info1_data = utils::ByteUtils_Concat({ cc7::MakeRange(protocol::PA_VERSION_V3), shared_info1, ephemeral_key});
    ek._key = algorithms().v3.kdfX963().deriveKeyBytes(shared_secret->getKeyData(), {
        { cc7::crypto::KDF_PARAM_INFO,     cc7::crypto::Parameter::ref(info1_data) }
    });
    return ek;
}

// ----------------------------------------------------------------------------------------------
// MARK: - Private encryption / decryption -
//

static void _Encrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const cc7::ByteRange & data, const cc7::ByteRange & iv, ECIESCryptogram & out_cryptogram)
{
    if (iv.size() != ECIESEnvelopeKey::IvSize) {
        throw std::logic_error("Wrong IV size");
    }
    out_cryptogram.body = algorithms().v3.aes128cbc().encrypt(ek.encKey(), iv, data);
    // Keep size of encrypted data
    auto encryptedDataSize = out_cryptogram.body.size();
    // mac = MAC(body || S2)
    out_cryptogram.body.append(info2);
    out_cryptogram.mac = algorithms().v3.hmacWithSha256().token(ek.macKey(), out_cryptogram.body);
    // set encrypted data size back to original value
    out_cryptogram.body.resize(encryptedDataSize);
}

static void _Decrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const ECIESCryptogram & cryptogram, const cc7::ByteRange & iv, cc7::ByteArray & out_data)
{
    if (iv.size() != ECIESEnvelopeKey::IvSize) {
        throw std::logic_error("Wrong IV size");
    }
    // Prepare data for HMAC calculation
    auto data_for_mac = cryptogram.body;
    data_for_mac.append(info2);
    auto mac = algorithms().v3.hmacWithSha256().token(ek.macKey(), data_for_mac);
    // Verify calculated mac
    if (!cc7::ConstTimeEqual(mac, cryptogram.mac)) {
        throw std::domain_error("MAC doesn't match");
    }
    // Decrypt data
    out_data = algorithms().v3.aes128cbc().decrypt(ek.encKey(), iv, cryptogram.body);
}

static cc7::ByteArray _BuildSharedInfo2(const cc7::ByteRange & sh2, const cc7::ByteRange & ephemeral_key, const cc7::ByteRange & nonce, const ECIESParameters & params)
{
    auto timestamp = cc7::ToBigEndian(params.timestamp);
    return utils::ByteUtils_Join({ sh2, nonce, cc7::MakeRange(timestamp), ephemeral_key, params.associatedData });
}

// ----------------------------------------------------------------------------------------------
// MARK: - Encryptor class -
//

ECIESEncryptor::ECIESEncryptor(const cc7::crypto::PublicKeyPtr & public_key, const cc7::ByteRange & shared_info1, const cc7::ByteRange & shared_info2) :
_public_key(public_key),
_shared_info1(shared_info1),
_shared_info2(shared_info2)
{
}

ECIESEncryptor::ECIESEncryptor(const ECIESEnvelopeKey & envelope_key, const cc7::ByteRange & shared_info2) :
_envelope_key(envelope_key),
_shared_info2(shared_info2)
{
}

// Getters & Setters

const cc7::crypto::PublicKeyPtr & ECIESEncryptor::publicKey() const
{
    return _public_key;
}

const ECIESEnvelopeKey & ECIESEncryptor::envelopeKey() const
{
    return _envelope_key;
}

const cc7::ByteArray & ECIESEncryptor::sharedInfo1() const
{
    return _shared_info1;
}

void ECIESEncryptor::setSharedInfo1(const cc7::ByteRange & shared_info1)
{
    _shared_info1 = shared_info1;
}

const cc7::ByteArray & ECIESEncryptor::sharedInfo2() const
{
    return _shared_info2;
}

void ECIESEncryptor::setSharedInfo2(const cc7::ByteRange & shared_info2)
{
    _shared_info2 = shared_info2;
}

bool ECIESEncryptor::canEncryptRequest() const
{
    return _public_key != nullptr;
}

bool ECIESEncryptor::canDecryptResponse() const
{
    return _envelope_key.isValid();
}


// MARK: - Encryption & Decryption

ErrorCode ECIESEncryptor::encryptRequest(const cc7::ByteRange & data, const ECIESParameters & parameters, ECIESCryptogram & out_cryptogram)
{
    if (canEncryptRequest()) {
        try {
            _envelope_key = ECIESEnvelopeKey::fromPublicKey(_public_key, _shared_info1, out_cryptogram.key);
            if (_envelope_key.isValid()) {
                out_cryptogram.nonce = cc7::crypto::GetRandomData(ECIESEnvelopeKey::NonceSize);
                auto iv = _envelope_key.deriveIvForNonce(out_cryptogram.nonce);
                auto info2 = _BuildSharedInfo2(_shared_info2, out_cryptogram.key, out_cryptogram.nonce, parameters);
                _Encrypt(_envelope_key, info2, data, iv, out_cryptogram);
                return EC_Ok;
            }
        } catch (std::exception & e) {
            CC7_LOG("ECIESEncryptor::encryptRequest fail %s", e.what());
            _envelope_key.invalidate();
        }
        return EC_Encryption;
    }
    return EC_WrongState;
}

ErrorCode ECIESEncryptor::decryptResponse(const ECIESCryptogram & cryptogram, const ECIESParameters & parameters, cc7::ByteArray & out_data)
{
    if (canDecryptResponse()) {
        auto result = EC_Encryption;
        try {
            auto iv = _envelope_key.deriveIvForNonce(cryptogram.nonce);
            auto info2 = _BuildSharedInfo2(_shared_info2, cc7::ByteRange(), cryptogram.nonce, parameters);
            _Decrypt(_envelope_key, info2, cryptogram, iv, out_data);
            result = EC_Ok;
        } catch (std::exception & e) {
            CC7_LOG("ECIESEncryptor::decryptResponse fail %s", e.what());
        }
        _envelope_key.invalidate();
        return result;
    }
    return EC_WrongState;
}


// ----------------------------------------------------------------------------------------------
// MARK: - Decryptor class -
//

ECIESDecryptor::ECIESDecryptor(const cc7::crypto::PrivateKeyPtr & private_key, const cc7::ByteRange & shared_info1, const cc7::ByteRange & shared_info2) :
_private_key(private_key),
_shared_info1(shared_info1),
_shared_info2(shared_info2)
{
}

ECIESDecryptor::ECIESDecryptor(const ECIESEnvelopeKey & envelope_key, const cc7::ByteRange & shared_info2) :
_envelope_key(envelope_key),
_shared_info2(shared_info2)
{
}

// Setters & Getters

const cc7::crypto::PrivateKeyPtr & ECIESDecryptor::privateKey() const
{
    return _private_key;
}

const ECIESEnvelopeKey & ECIESDecryptor::envelopeKey() const
{
    return _envelope_key;
}

const cc7::ByteArray & ECIESDecryptor::sharedInfo1() const
{
    return _shared_info1;
}

void ECIESDecryptor::setSharedInfo1(const cc7::ByteRange & shared_info1)
{
    _shared_info1 = shared_info1;
}

const cc7::ByteArray & ECIESDecryptor::sharedInfo2() const
{
    return _shared_info2;
}

void ECIESDecryptor::setSharedInfo2(const cc7::ByteRange & shared_info2)
{
    _shared_info2 = shared_info2;
}

bool ECIESDecryptor::canEncryptResponse() const
{
    return _envelope_key.isValid();
}

bool ECIESDecryptor::canDecryptRequest() const
{
    return _private_key != nullptr;
}


// MARK: - Encryption & Decryption

ErrorCode ECIESDecryptor::decryptRequest(const ECIESCryptogram & cryptogram, const ECIESParameters & parameters, cc7::ByteArray & out_data)
{
    if (canDecryptRequest()) {
        try {
            _envelope_key = ECIESEnvelopeKey::fromPrivateKey(_private_key, cryptogram.key, _shared_info1);
            if (_envelope_key.isValid()) {
                auto iv = _envelope_key.deriveIvForNonce(cryptogram.nonce);
                auto info2 = _BuildSharedInfo2(_shared_info2, cryptogram.key, cryptogram.nonce, parameters);
                _Decrypt(_envelope_key, info2, cryptogram, iv, out_data);
                return EC_Ok;
            }
        } catch (std::exception & e) {
            CC7_LOG("ECIESDecryptor::decryptRequest fail %s", e.what());
            _envelope_key.invalidate();
        }
        return EC_Encryption;
    }
    return EC_WrongState;
}

ErrorCode ECIESDecryptor::encryptResponse(const cc7::ByteRange & data, const ECIESParameters & parameters, ECIESCryptogram & out_cryptogram)
{
    if (canEncryptResponse()) {
        auto result = EC_Encryption;
        try {
            out_cryptogram.nonce = cc7::crypto::GetRandomData(ECIESEnvelopeKey::NonceSize);
            auto iv = _envelope_key.deriveIvForNonce(out_cryptogram.nonce);
            auto info2 = _BuildSharedInfo2(_shared_info2, cc7::ByteRange(), out_cryptogram.nonce, parameters);
            _Encrypt(_envelope_key, info2, data, iv, out_cryptogram);
            result = EC_Ok;
        } catch (std::exception & e) {
            CC7_LOG("ECIESDecryptor::encryptResponse fail %s", e.what());
        }
        _envelope_key.invalidate();
        return result;
    }
    return EC_WrongState;
}

// ----------------------------------------------------------------------------------------------
// MARK: - Parameters -
//

ECIESParameters::ECIESParameters() :
timestamp(0)
{
}

// ----------------------------------------------------------------------------------------------
// MARK: - Utilities -
//

cc7::ByteArray ECIESUtils::buildAssociatedData(const std::string &applicationKey, const std::string & temporaryKeyId, const std::string &activationId) {
    auto version = Version_GetMaxSupportedHttpProtocolVersion(Version_Latest);
    cc7::ByteArray ad;
    if (activationId.empty()) {
        // Application scope
        ad = utils::ByteUtils_Join({ cc7::MakeRange(version), cc7::MakeRange(applicationKey), cc7::MakeRange(temporaryKeyId) });
    } else {
        // Activation scope
        ad = utils::ByteUtils_Join({ cc7::MakeRange(version), cc7::MakeRange(applicationKey), cc7::MakeRange(activationId), cc7::MakeRange(temporaryKeyId) });
    }
    return ad;
}

} // namespace powerAuth
