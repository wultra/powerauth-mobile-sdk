/*
 * Copyright 2018 Wultra s.r.o.
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

#include <cc7/jni/JniHelper.h>
#include "../crypto/CryptoUtils.h"
#include "EcPublicKeyJNI.h"
#include "EcPrivateKeyJNI.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CryptoUtils
#define CC7_JNI_CPP_CLASS           NA
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;
using namespace io::getlime::powerAuth::jni;

extern "C" {

//
// public static native EcKeyPair ecGenerateKeyPair()
//
CC7_JNI_METHOD(jobject, ecGenerateKeyPair)
{
    jobject result = nullptr;
    EC_KEY * key_pair = nullptr;
    EcPrivateKeyJNI * cpp_private_key = nullptr;
    EcPublicKeyJNI * cpp_public_key = nullptr;
    crypto::BNContext ctx;

    do {
        key_pair = crypto::ECC_GenerateKeyPair();
        if (key_pair == nullptr) {
            CC7_ASSERT(false, "Failed to generate EC key-pair");
            break;
        }
        cpp_private_key = EcPrivateKeyJNI::createFromBytes(crypto::ECC_ExportPrivateKey(key_pair, ctx), ctx);
        if (cpp_private_key == nullptr) {
            break;
        }
        cpp_public_key = EcPublicKeyJNI::createFromBytes(crypto::ECC_ExportPublicKey(key_pair, ctx), ctx);
        if (cpp_public_key == nullptr) {
            break;
        }
        auto java_private_key = CreateJavaEcPrivateKeyFromCppObject(env, cpp_private_key);
        cpp_private_key = nullptr;  // already captured or deleted in "Create" function
        if (java_private_key == nullptr) {
            break;
        }
        auto java_public_key = CreateJavaEcPublicKeyFromCppObject(env, cpp_public_key);
        cpp_public_key = nullptr;   // already captured or deleted in "Create" function
        if (java_public_key == nullptr) {
            break;
        }
        auto private_key_object_signature = std::string(CC7_JNI_MODULE_CLASS_SIGNATURE("EcPrivateKey"));
        auto public_key_object_signature = std::string(CC7_JNI_MODULE_CLASS_SIGNATURE("EcPublicKey"));
        std::string constructor_signature = "(" + private_key_object_signature + public_key_object_signature + ")V";
        result = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("EcKeyPair"), constructor_signature.c_str(), java_private_key, java_public_key);

    } while (false);

    if (key_pair != nullptr) {
        EC_KEY_free(key_pair);
    }
    delete cpp_private_key;
    delete cpp_public_key;
    return result;
}

//
// public static native byte[] ecdsaValidateSignature(byte[] data, byte[] signature, EcPublicKey publicKey)
//
CC7_JNI_METHOD_PARAMS(jboolean, ecdsaValidateSignature, jbyteArray data, jbyteArray signature, jobject publicKey)
{
    if (data == nullptr || signature == nullptr || publicKey == nullptr || env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return false;
    }

    bool result = false;

    // Convert data objects
    auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
    auto cpp_signature = cc7::jni::CopyFromJavaByteArray(env, signature);
    auto cpp_publicKey = GetEcPublicKeyFromJavaObject(env, publicKey);

    if (cpp_publicKey != nullptr) {
        // Validate signature
        result = crypto::ECDSA_ValidateSignature(cpp_data, cpp_signature, cpp_publicKey->keyPtr());
    }
    return result;
}

//
// public static native byte[] ecdsaComputeSignature(byte[] data, EcPrivateKey privateKey);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, ecdsaComputeSignature, jbyteArray data, jobject privateKey)
{
    if (data == nullptr || privateKey == nullptr || env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return nullptr;
    }

    jbyteArray result = nullptr;

    // Convert data objects
    auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
    auto cpp_privateKey = GetEcPrivateKeyFromJavaObject(env, privateKey);

    if (cpp_privateKey != nullptr) {
        // Validate signature
        cc7::ByteArray cpp_result;
        if (crypto::ECDSA_ComputeSignature(cpp_data, cpp_privateKey->keyPtr(), cpp_result)) {
            result = cc7::jni::CopyToJavaByteArray(env, cpp_result);
        }
    }
    return result;
}

//
// public static native byte[] ecdhComputeSharedSecret(EcPublicKey publicKey, EcPrivateKey privateKey)
//
CC7_JNI_METHOD_PARAMS(jbyteArray, ecdhComputeSharedSecret, jobject publicKey, jobject privateKey)
{
    if (privateKey == nullptr || publicKey == nullptr || env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return nullptr;
    }

    jbyteArray result = nullptr;

    // Convert data objects
    auto cpp_privateKey = GetEcPrivateKeyFromJavaObject(env, privateKey);
    auto cpp_publicKey = GetEcPublicKeyFromJavaObject(env, publicKey);

    if (cpp_privateKey != nullptr && cpp_publicKey != nullptr) {
        // Compute shared secret
        cc7::ByteArray cpp_result = crypto::ECDH_SharedSecret(cpp_publicKey->keyPtr(), cpp_privateKey->keyPtr());
        if (!cpp_result.empty()) {
            result = cc7::jni::CopyToJavaByteArray(env, cpp_result);
        }
    }
    return result;
}

//
// public static native byte[] hashSha256(byte[] data)
//
CC7_JNI_METHOD_PARAMS(jbyteArray, hashSha256, jbyteArray data)
{
    if (data == nullptr || env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return nullptr;
    }

    // Convert data objects & calculate hash
    auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
    auto hash = crypto::SHA256(cpp_data);
    return cc7::jni::CopyToJavaByteArray(env, hash);
}

//
// public static native byte[] hmacSha256(byte[] data, byte[] key, int outputLength)
//
CC7_JNI_METHOD_PARAMS(jbyteArray, hmacSha256, jbyteArray data, jbyteArray key, jint outputLength)
{
    if (data == nullptr || key == nullptr || env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return nullptr;
    }
    if (outputLength < 0) {
        CC7_ASSERT(false, "Invalid 'outputLength' parameter.");
        return nullptr;
    }
    // Convert data objects
    auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
    auto cpp_key = cc7::jni::CopyFromJavaByteArray(env, key);
    auto mac = crypto::HMAC_SHA256(cpp_data, cpp_key, (size_t)outputLength);
    return cc7::jni::CopyToNullableJavaByteArray(env, mac);
}

//
// public static native byte[] randomBytes(int count);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, randomBytes, jint count)
{
    if (env == nullptr) {
        CC7_ASSERT(false, "Missing required parameter.");
        return nullptr;
    }
    if (count < 0) {
        CC7_ASSERT(false, "Invalid 'count' parameter.");
        return nullptr;
    }
    // Generate random data
    auto random_bytes = crypto::GetRandomData((size_t)count, true);
    return cc7::jni::CopyToNullableJavaByteArray(env, random_bytes);
}

} // extern "C"
