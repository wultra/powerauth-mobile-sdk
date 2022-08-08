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
#include "crypto/CryptoUtils.h"
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
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

    cc7::ByteArray ECIESEnvelopeKey::deriveIvForNonce(const cc7::ByteRange & nonce) const
    {
        return protocol::DeriveSecretKeyFromIndex(ivKey(), nonce);
    }
    
    ECIESEnvelopeKey ECIESEnvelopeKey::fromPublicKey(const cc7::ByteRange & public_key, const cc7::ByteRange & shared_info1, cc7::ByteArray & out_ephemeral_key)
    {
        crypto::BNContext ctx;
        EC_KEY *pubk = nullptr, *ephemeral = nullptr;
        ECIESEnvelopeKey ek;
        do {
            pubk = crypto::ECC_ImportPublicKey(nullptr, public_key, ctx);
            if (!pubk) {
                break;
            }
            ephemeral = crypto::ECC_GenerateKeyPair();
            if (!ephemeral) {
                break;
            }
            auto sharedSecret = crypto::ECDH_SharedSecret(pubk, ephemeral);
            if (sharedSecret.empty()) {
                break;
            }
            out_ephemeral_key = crypto::ECC_ExportPublicKey(ephemeral, ctx);
            if (out_ephemeral_key.empty()) {
                break;
            }
            // Concat shared_info1 + ephemeral key.
            cc7::ByteArray info1_data;
            info1_data.reserve(shared_info1.size() + out_ephemeral_key.size());
            info1_data.assign(shared_info1);
            info1_data.append(out_ephemeral_key);
            // Derive shared secret
            ek._key = crypto::ECDH_KDF_X9_63_SHA256(sharedSecret, info1_data, EnvelopeKeySize);
            
        } while (false);
        
        // Releace OpenSSL resources
        EC_KEY_free(pubk);
        EC_KEY_free(ephemeral);
        
        return ek;
    }
    
    ECIESEnvelopeKey ECIESEnvelopeKey::fromPrivateKey(const cc7::ByteArray & private_key, const cc7::ByteRange & ephemeral_key, const cc7::ByteRange & shared_info1)
    {
        crypto::BNContext ctx;
        EC_KEY *privk = nullptr, *ephemeral = nullptr;
        ECIESEnvelopeKey ek;
        
        do {
            privk = crypto::ECC_ImportPrivateKey(nullptr, private_key);
            if (!privk) {
                break;
            }
            ephemeral = crypto::ECC_ImportPublicKey(nullptr, ephemeral_key);
            if (!ephemeral) {
                break;
            }
            auto sharedSecret = crypto::ECDH_SharedSecret(ephemeral, privk);
            if (sharedSecret.empty()) {
                break;
            }
            // Concat shared_info1 + ephemeral key.
            cc7::ByteArray info1_data;
            info1_data.reserve(shared_info1.size() + ephemeral_key.size());
            info1_data.assign(shared_info1);
            info1_data.append(ephemeral_key);
            // Derive shared secret
            ek._key = crypto::ECDH_KDF_X9_63_SHA256(sharedSecret, info1_data, EnvelopeKeySize);
            
        } while (false);
        
        // Releace OpenSSL resources
        EC_KEY_free(privk);
        EC_KEY_free(ephemeral);
        
        return ek;
    }

    // ----------------------------------------------------------------------------------------------
    // MARK: - Private encryption / decryption -
    //
    
    static ErrorCode _Encrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const cc7::ByteRange & data, const cc7::ByteRange & iv, ECIESCryptogram & out_cryptogram)
    {
        if (iv.size() != ECIESEnvelopeKey::IvSize) {
            return EC_Encryption;
        }
        out_cryptogram.body = crypto::AES_CBC_Encrypt_Padding(ek.encKey(), iv, data);
        if (out_cryptogram.body.empty()) {
            return EC_Encryption;
        }
        // Keep size of encrypted data
        const size_t encryptedDataSize = out_cryptogram.body.size();
        // mac = MAC(body || S2)
        out_cryptogram.body.append(info2);
        out_cryptogram.mac = crypto::HMAC_SHA256(out_cryptogram.body, ek.macKey());
        if (out_cryptogram.mac.empty()) {
            return EC_Encryption;
        }
        // set encrypted data size back to original value
        out_cryptogram.body.resize(encryptedDataSize);
        return EC_Ok;
    }
    
    static ErrorCode _Decrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const ECIESCryptogram & cryptogram, const cc7::ByteRange & iv, cc7::ByteArray & out_data)
    {
        if (iv.size() != ECIESEnvelopeKey::IvSize) {
            return EC_Encryption;
        }
        // Prepare data for HMAC calculation
        auto data_for_mac = cryptogram.body;
        data_for_mac.append(info2);
        auto mac = crypto::HMAC_SHA256(data_for_mac, ek.macKey());
        // Verify calculated mac
        if (mac.empty() || mac != cryptogram.mac) {
            return EC_Encryption;
        }
        // Decrypt data
        bool error = true;
        out_data = crypto::AES_CBC_Decrypt_Padding(ek.encKey(), iv, cryptogram.body, &error);
        return error ? EC_Encryption : EC_Ok;
    }
    
    // ----------------------------------------------------------------------------------------------
    // MARK: - Encryptor class -
    //
    
    ECIESEncryptor::ECIESEncryptor(const cc7::ByteRange & public_key, const cc7::ByteRange & shared_info1, const cc7::ByteRange & shared_info2) :
        _public_key(public_key),
        _shared_info1(shared_info1),
        _shared_info2(shared_info2)
    {
    }
    
    ECIESEncryptor::ECIESEncryptor(const ECIESEnvelopeKey & envelope_key, const cc7::ByteRange & iv_for_decryption, const cc7::ByteRange & shared_info2) :
        _envelope_key(envelope_key),
        _shared_info2(shared_info2),
        _iv_for_decryption(iv_for_decryption)
    {
    }
    
    // Getters & Setters
    
    const cc7::ByteArray & ECIESEncryptor::publicKey() const
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

    const cc7::ByteArray & ECIESEncryptor::ivForDecryption() const
    {
        return _iv_for_decryption;
    }
    
    bool ECIESEncryptor::canEncryptRequest() const
    {
        return !_public_key.empty();
    }
    
    bool ECIESEncryptor::canDecryptResponse() const
    {
        return _envelope_key.isValid() && (_iv_for_decryption.size() == ECIESEnvelopeKey::IvSize);
    }
    
    
    // MARK: - Encryption & Decryption
    
    ErrorCode ECIESEncryptor::encryptRequest(const cc7::ByteRange & data, ECIESCryptogram & out_cryptogram)
    {
        if (canEncryptRequest()) {
            _envelope_key = ECIESEnvelopeKey::fromPublicKey(_public_key, _shared_info1, out_cryptogram.key);
            if (_envelope_key.isValid()) {
                out_cryptogram.nonce = crypto::GetRandomData(ECIESEnvelopeKey::NonceSize);
                _iv_for_decryption = _envelope_key.deriveIvForNonce(out_cryptogram.nonce);
                return _Encrypt(_envelope_key, _shared_info2, data, _iv_for_decryption, out_cryptogram);
            }
            return EC_Encryption;
        }
        return EC_WrongState;
    }
    
    ErrorCode ECIESEncryptor::decryptResponse(const ECIESCryptogram & cryptogram, cc7::ByteArray & out_data)
    {
        if (canDecryptResponse()) {
            return _Decrypt(_envelope_key, _shared_info2, cryptogram, _iv_for_decryption, out_data);
        }
        return EC_WrongState;
    }
    
    
    // ----------------------------------------------------------------------------------------------
    // MARK: - Decryptor class -
    //
    
    ECIESDecryptor::ECIESDecryptor(const cc7::ByteArray & private_key, const cc7::ByteRange & shared_info1, const cc7::ByteRange & shared_info2) :
        _private_key(private_key),
        _shared_info1(shared_info1),
        _shared_info2(shared_info2)
    {
    }
    
    ECIESDecryptor::ECIESDecryptor(const ECIESEnvelopeKey & envelope_key, const cc7::ByteRange & iv_for_encryption, const cc7::ByteRange & shared_info2) :
        _envelope_key(envelope_key),
        _shared_info2(shared_info2),
        _iv_for_encryption(iv_for_encryption)
    {
    }
    
    // Setters & Getters
    
    const cc7::ByteArray & ECIESDecryptor::privateKey() const
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

    const cc7::ByteArray & ECIESDecryptor::ivForEncryption() const
    {
        return _iv_for_encryption;
    }
    
    bool ECIESDecryptor::canEncryptResponse() const
    {
        return _envelope_key.isValid() && (_iv_for_encryption.size() == ECIESEnvelopeKey::IvSize);
    }
    
    bool ECIESDecryptor::canDecryptRequest() const
    {
        return !_private_key.empty();
    }
    
    
    // MARK: - Encryption & Decryption
    
    ErrorCode ECIESDecryptor::decryptRequest(const ECIESCryptogram & cryptogram, cc7::ByteArray & out_data)
    {
        if (canDecryptRequest()) {
            _envelope_key = ECIESEnvelopeKey::fromPrivateKey(_private_key, cryptogram.key, _shared_info1);
            if (_envelope_key.isValid()) {
                _iv_for_encryption = _envelope_key.deriveIvForNonce(cryptogram.nonce);
                return _Decrypt(_envelope_key, _shared_info2, cryptogram, _iv_for_encryption, out_data);
            }
            return EC_Encryption;
        }
        return EC_WrongState;
    }
    
    ErrorCode ECIESDecryptor::encryptResponse(const cc7::ByteRange & data, ECIESCryptogram & out_cryptogram)
    {
        if (canEncryptResponse()) {
            return _Encrypt(_envelope_key, _shared_info2, data, _iv_for_encryption, out_cryptogram);
        }
        return EC_WrongState;
    }
    
} // io::getlime::powerAuth
} // io::getlime
} // io
