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

#include "SecretKeysPool.h"
#include "../model/Constants.h"
#include "../v4/PowerAuthKDF.h"
#include "../v4/PowerAuthAEAD.h"
#include "../v4/PowerAuthUKE.h"
#include "../v3/LegacyUKE.h"
#include "../v3/LegacyKDF.h"

using namespace cc7;

namespace powerAuth {
namespace common {

// MARK: - Debug

#define ENABLE_KDUMP 0  // set to 1 to enable full key access log
#define ENABLE_EDUMP 0  // set to 1 to enable exception log

#if ENABLE_KDUMP
static void _KDump(const std::string& name, const KT::KeyRef& key_material);
static void _KDump(const std::string& name, const KT::INPUT& tr, bool is_set, const KT::KeyRef& key_material);
static void _KDump(const std::string& name, const KT::KDF& tr, const KT::KeyRef& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::PKDF& tr, const KT::PKDFKeys& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::AEAD& tr, const KT::AEADKeys& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::UKE& tr, const KT::UKEKeys& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::CUSTOM& tr, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::Cipher& tr, const KT::CipherKeys& src, const KT::KeyRef& out);
// Legacy
static void _KDump(const std::string& name, const KT::LegacyUKE& tr, const KT::LegacyUKEKeys& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::LegacyKDF& tr, const KT::KeyRef& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::LegacyKDFIntKeys& src, const KT::KeyRef& out);
static void _KDump(const std::string& name, const KT::LegacyPBKDF2Keys& src, const KT::KeyRef& out);
#else
#define _KDump(...)
#endif

#if ENABLE_EDUMP
static void _EDump(const std::string& msg);
#else
#define _EDump(...)
#endif

// MARK: - Public methods

SecretKeysPool::SecretKeysPool(const Config& config) :
    _conf(config),
    _keys(new ByteRange[config.all_keys_count])
{
}

bool SecretKeysPool::isSet(int key_id) const
{
    validateKeyId(key_id, false);
    return !keyRange(key_id).empty();
}

void SecretKeysPool::setKey(int key_id, const KT::INPUT &tr, const ByteRange& key_material)
{
    validateKeyId(key_id, true);
    if (!keyRange(key_id).empty()) {
        throwError(EC_NotAllowed, "Input key " + keyName(key_id) + " is already set");
    }
    if (tr.keySize && tr.keySize != key_material.size()) {
        throwError(EC_NotAllowed, "Input key " + keyName(key_id) + " has wrong size");
    }
    _KDump(keyName(key_id), tr, true, key_material);
    allocateKey(key_id, key_material);
}

void SecretKeysPool::clearKey(int key_id)
{
    validateKeyId(key_id, true);
    keyRange(key_id).clear();
}

// MARK: - Get Key

ByteRange SecretKeysPool::getKey(int key_id, const KT::INPUT &tr)
{
    if (isSet(key_id)) {
        const auto& range = keyRange(key_id);
        if (!validateSize(tr.keySize, tr.allowEmpty, range.size())) {
            throwError(EC_NotAllowed, "Input key " + keyName(key_id) + " has wrong size");
        }
        _KDump(keyName(key_id), tr, false, range);
        return range;
    }
    throwError(EC_NotAllowed, "Input key " + keyName(key_id) + " is not set");
}

ByteRange SecretKeysPool::getKey(int key_id, const KT::KDF &tr, const KT::KeyProvider& source_key)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto out_size = tr.keySize ? tr.keySize : _conf.default_key_size;
    auto source = source_key();
    auto derived = algorithms().v4.kdf().derive(source, tr.label, ByteRange(), out_size);
    _KDump(keyName(key_id), tr, source, derived);
    return allocateKey(key_id, derived);
}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::PKDF& tr, const KT::PKDFProvider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    auto derived = algorithms().v4.pbkdf().derive(keys.password, keys.salt, tr.keySize);
    _KDump(keyName(key_id), tr, keys, derived);
    return allocateKey(key_id, derived);
}

ByteRange SecretKeysPool::getKey(int key_id, const KT::AEAD &tr, const KT::AEADProvider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    if (tr.keyContext.empty()) {
        throwError(EC_InternalError, "KeyContext is required in AEAD");
    }
    auto params = crypto::ParameterList {
        { crypto::PARAM_KEY_CONTEXT, crypto::Parameter::ref(MakeRange(tr.keyContext))}
    };
    const auto& aead = algorithms().v4.aead();
    ByteArray out;
    if (tr.mode == KT::ENCRYPT) {
        out = aead.seal(keys.kek, cc7::crypto::GetRandomData(12), keys.aad, keys.data, params);
    } else {
        out = aead.open(keys.kek, keys.aad, keys.data, params);
    }
    _KDump(keyName(key_id), tr, keys, out);
    return allocateKey(key_id, out);
}

ByteRange SecretKeysPool::getKey(int key_id, const KT::UKE &tr, const KT::UKEProvider &keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    const auto& uke = algorithms().v4.uke();
    ByteArray out;
    if (tr.mode == KT::ENCRYPT) {
        out = uke.wrap(keys.kek, keys.data);
    } else {
        out = uke.unwrap(keys.kek, keys.data);
    }
    _KDump(keyName(key_id), tr, keys, out);
    return allocateKey(key_id, out);
}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::CUSTOM& tr, const KT::CustomKeyProvider& derived_key)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto derived = derived_key();
    if (!validateSize(tr.keySize, tr.allowEmpty, derived.size())) {
        throwError(EC_NotAllowed, "Custom derived key " + keyName(key_id) + " has wrong size");
    }
    _KDump(keyName(key_id), tr, derived);
    return allocateKey(key_id, derived);
}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::Cipher& tr, const KT::CipherProvider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    cc7::ByteArray out;
    if (tr.mode == KT::ENCRYPT) {
        out = tr.cipher->encrypt(keys.key, keys.iv, keys.data);
    } else {
        out = tr.cipher->decrypt(keys.key, keys.iv, keys.data);
    }
    _KDump(keyName(key_id), tr, keys, out);
    return allocateKey(key_id, out);
}

// MARK: - Legacy algorithms

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::LegacyUKE& tr, const KT::LegacyUKEProvider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    const auto& uke = algorithms().v3.uke();
    ByteArray out;
    if (tr.mode == KT::ENCRYPT) {
        out = uke.wrap(keys.kek, keys.data);
    } else {
        out = uke.unwrap(keys.kek, keys.data);
    }
    _KDump(keyName(key_id), tr, keys, out);
    return allocateKey(key_id, out);

}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::LegacyKDF& tr, const KT::LegacyKDFProvider& source_key)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto source = source_key();
    auto derived = algorithms().v3.kdf().derive(source, tr.index);
    _KDump(keyName(key_id), tr, source, derived);
    return allocateKey(key_id, derived);
}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::LegacyKDFIntProvider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    auto derived = algorithms().v3.kdfInternal().derive(keys.key, keys.index);
    _KDump(keyName(key_id), keys, derived);
    return allocateKey(key_id, derived);
}

cc7::ByteRange SecretKeysPool::getKey(int key_id, const KT::LegacyPBKDF2Provider& keys_provider)
{
    if (isSet(key_id)) {
        _KDump(keyName(key_id), keyRange(key_id));
        return keyRange(key_id);
    }
    auto keys = keys_provider();
    auto derived = algorithms().v3.pbkdf2WithSha1().deriveKeyBytes(keys.password, {
        { crypto::KDF_PARAM_SALT, crypto::Parameter::ref(keys.salt) },
        { crypto::KDF_PARAM_ITERATIONS, crypto::Parameter::take((size_t)keys.iterations) },
    });
    _KDump(keyName(key_id), keys, derived);
    return allocateKey(key_id, derived);
}

// MARK: - Private methods

void SecretKeysPool::validateKeyId(int key_id, bool for_write) const
{
    if (key_id < 0 || key_id >= _conf.all_keys_count) {
        throwError(EC_WrongParameter, "Invalid secret key identifier: " + std::to_string(key_id));
    }
    if (for_write && key_id >= _conf.input_output_keys_end) {
        throwError(EC_WrongParameter, "Key " + keyName(key_id) + " is not writable from outside");
    }
}

bool SecretKeysPool::validateSize(size_t expected_size, bool allow_empty, size_t actual_size) const noexcept
{
    if (expected_size) {
        // size specified, compare sizes
        return expected_size == actual_size;
    } else {
        // size not specified, just test whether empty data are allowed
        if (actual_size == 0) {
            return allow_empty;
        }
        return true;
    }
}

ByteRange& SecretKeysPool::keyRange(int key_id)
{
    return _keys[key_id];
}

const ByteRange& SecretKeysPool::keyRange(int key_id) const
{
    return _keys[key_id];
}

std::string SecretKeysPool::keyName(int key_id) const noexcept
{
    if (_conf.key_name_resolver) {
        return _conf.key_name_resolver(key_id);
    }
    return "#" + std::to_string(key_id);
}

const ByteRange& SecretKeysPool::allocateKey(int key_id, const cc7::ByteRange &key_material)
{
    auto key_size = key_material.size();
    ByteArray * blob = nullptr;
    if (key_size <= _conf.heap_size) {
        // Look for heap blob with enough space. Iterate from end, because it's higher chance
        // to find such blob at the end of the array.
        for (auto it = _heap.rbegin(); it != _heap.rend(); ++it) {
            if (_conf.heap_size - (*it)->size() >= key_size) {
                blob = &*(*it);
                break;
            }
        }
        if (!blob) {
            // No blob with enough free space found, allocate new heap blob
            auto new_blob = std::make_unique<ByteArray>();
            new_blob->reserve(_conf.heap_size);
            blob = &(*new_blob);
            _heap.push_back(std::move(new_blob));
        }
    } else {
        // requested key is grater than heap size, allocate one buffer just for the requested data
        auto new_blob = std::make_unique<ByteArray>();
        new_blob->reserve(key_size);
        blob = &(*new_blob);
        // Put array to a separate list of allocated buffers. We don't want to
        // mix this with regular allocation pool
        _to_destroy.push_back(std::move(new_blob));
    }
    auto offset = blob->size();
    blob->append(key_material);
    // store and return allocated key range
    auto& out_range = keyRange(key_id);
    out_range = blob->byteRange().subRange(offset, key_size);
    return out_range;
}

void SecretKeysPool::throwError(ErrorCode ec, const std::string & message)
{
    _EDump(message);
    throw Exception(ec, message);
}

#if ENABLE_KDUMP
static void _KDump(const std::string& name, const KT::KeyRef& key_material)
{
    // cached
    fprintf(stdout, "    get %s: ~~> %s\n", name.c_str(), key_material.hexadecimal().c_str());
}

static void _KDump(const std::string& name, const KT::INPUT& tr, bool is_set, const KT::KeyRef& key_material)
{
    if (is_set) {
        fprintf(stdout, "    set %s:  <- %s\n", name.c_str(), key_material.hexadecimal().c_str());
    } else {
        fprintf(stdout, "    get %s:  -> %s\n", name.c_str(), key_material.hexadecimal().c_str());
    }
}

static void _KDump(const std::string& name, const KT::KDF& tr, const KT::KeyRef& src, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s:  -> %s\n"
                    "          = KDF\n"
                    "              K: %s\n"
                    "              L: %s\n", name.c_str(), out.hexadecimal().c_str(), src.hexadecimal().c_str(), tr.label.c_str());
}

static void _KDump(const std::string& name, const KT::PKDF& tr, const KT::PKDFKeys& src, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s:  -> %s\n"
                    "          = PKDF\n"
                    "              P: %s\n"
                    "              S: %s\n", name.c_str(), out.hexadecimal().c_str(), src.password.hexadecimal().c_str(), src.salt.hexadecimal().c_str());
}

static void _KDump(const std::string& name, const KT::AEAD& tr, const KT::AEADKeys& src, const KT::KeyRef& out)
{
    if (tr.mode == KT::ENCRYPT) {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = AEAD.seal\n"
                        "              K: %s\n"
                        "              D: %s\n"
                        "              A: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str(), src.aad.hexadecimal().c_str());
    } else {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = AEAD.open\n"
                        "              K: %s\n"
                        "              D: %s\n"
                        "              A: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str(), src.aad.hexadecimal().c_str());
    }
}

static void _KDump(const std::string& name, const KT::UKE& tr, const KT::UKEKeys& src, const KT::KeyRef& out)
{
    if (tr.mode == KT::ENCRYPT) {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = UKE.wrap\n"
                        "              K: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str());

    } else {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = UKE.unwrap\n"
                        "              K: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str());
    }
}

static void _KDump(const std::string& name, const KT::Cipher& tr, const KT::CipherKeys& src, const KT::KeyRef& out)
{
    if (tr.mode == KT::ENCRYPT) {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = %s.encrypt\n"
                        "              K: %s\n"
                        "              I: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), tr.cipher->getAlgorithmName().c_str(), src.key.hexadecimal().c_str(), src.iv.hexadecimal().c_str(), src.data.hexadecimal().c_str());

    } else {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = %s.decrypt\n"
                        "              K: %s\n"
                        "              I: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), tr.cipher->getAlgorithmName().c_str(), src.key.hexadecimal().c_str(), src.iv.hexadecimal().c_str(), src.data.hexadecimal().c_str());
    }
}

static void _KDump(const std::string& name, const KT::CUSTOM& tr, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s: [#] -> %s\n", name.c_str(), out.hexadecimal().c_str());
}

// Legacy

static void _KDump(const std::string& name, const KT::LegacyUKE& tr, const KT::LegacyUKEKeys& src, const KT::KeyRef& out)
{
    if (tr.mode == KT::ENCRYPT) {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = LegacyUKE.wrap\n"
                        "              K: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str());

    } else {
        fprintf(stdout, "    get %s:  -> %s\n"
                        "          = LegacyUKE.unwrap\n"
                        "              K: %s\n"
                        "              D: %s\n", name.c_str(), out.hexadecimal().c_str(), src.kek.hexadecimal().c_str(), src.data.hexadecimal().c_str());
    }
}

static void _KDump(const std::string& name, const KT::LegacyKDF& tr, const KT::KeyRef& src, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s:  -> %s\n"
                    "          = LegacyKDF\n"
                    "              K: %s\n"
                    "              I: %lld\n", name.c_str(), out.hexadecimal().c_str(), src.hexadecimal().c_str(), tr.index);
}

static void _KDump(const std::string& name, const KT::LegacyKDFIntKeys& src, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s:  -> %s\n"
                    "          = LegacyKDFInternal\n"
                    "              K: %s\n"
                    "              I: %s\n", name.c_str(), out.hexadecimal().c_str(), src.key.hexadecimal().c_str(), src.index.hexadecimal().c_str());
}

static void _KDump(const std::string& name, const KT::LegacyPBKDF2Keys& src, const KT::KeyRef& out)
{
    fprintf(stdout, "    get %s:  -> %s\n"
                    "          = LegacyPBKDF2\n"
                    "              P: %s\n"
                    "              S: %s\n"
                    "              I: %zu\n", name.c_str(), out.hexadecimal().c_str(), src.password.hexadecimal().c_str(), src.salt.hexadecimal().c_str(), src.iterations);
}

#endif

#if ENABLE_EDUMP
static void _EDump(const std::string& msg)
{
    fprintf(stdout, " ## Fail: %s\n", msg.c_str());
}
#endif


} // namespace common
} // namespace powerAuth
