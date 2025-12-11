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

#include "NativeHelper.h"
#include "SecureDataJNI.h"
#include <PowerAuth/Algorithms.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CryptoUtils
#define CC7_JNI_CPP_CLASS           NA
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;

extern "C" {

// NOTE: This is a legacy interface that will be replaced with a new functionality in future SDK versions.
//       Due to a compatibility reasons, all native functions doesn't throw an exceptions.

//
// public static native EcKeyPair ecGenerateKeyPair()
//
CC7_JNI_STATIC_METHOD(jobject, ecGenerateKeyPair)
{
    NH_TRY
    {
        auto key_pair = algorithms().v3.p256().generateKeyPair();
        const auto& specs = NH_SPECS();
        auto private_key = jni.toJava(specs.ecPrivateKey, key_pair->getPrivateKeyPtr());
        auto public_key  = jni.toJava(specs.ecPublicKey, key_pair->getPublicKeyPtr());
        return jni.createObject(specs.ecKeyPair.methods.init, private_key, public_key).object();
    }
    NH_NO_THROW(nullptr)
}

//
// static byte[] ecdsaComputeSignature(@Nullable byte[] data, @NonNull EcPrivateKey privateKey)
//
CC7_JNI_STATIC_METHOD_PARAMS(jboolean, ecdsaValidateSignature, jbyteArray data, jbyteArray signature, jobject publicKey)
{
    NH_TRY
    {
        jni.requireParameter(signature, "signature");
        jni.requireParameter(publicKey, "publicKey");
        const auto& specs = NH_SPECS();
        auto cpp_data = jni.fromJava(data);
        auto cpp_sign = jni.fromJava(signature);
        auto cpp_public_key = jni.fromJava<cc7::crypto::PublicKey>(specs.ecPublicKey, publicKey);
        try {
            return algorithms().v3.ecdsaWithSha256().verify(*cpp_public_key, cpp_sign, cpp_data);
        } catch (std::exception & e) {
            return false;
        }
    }
    NH_NO_THROW(false)
}

//
// static byte[] ecdsaComputeSignature(@Nullable byte[] data, @NonNull EcPrivateKey privateKey)
//
CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, ecdsaComputeSignature, jbyteArray data, jobject privateKey)
{
    NH_TRY
    {
        jni.requireParameter(privateKey, "privateKey");
        const auto& specs = NH_SPECS();
        auto cpp_data = jni.fromJava(data);
        auto cpp_private_key = jni.fromJava<cc7::crypto::PrivateKey>(specs.ecPrivateKey, privateKey);
        auto cpp_sign = algorithms().v3.ecdsaWithSha256().sign(*cpp_private_key, cpp_data);
        return jni.toJava(cpp_sign);
    }
    NH_NO_THROW(nullptr)
}

//
// static SecureData ecdhComputeSharedSecret(@NonNull EcPublicKey publicKey, @NonNull EcPrivateKey privateKey)
//
CC7_JNI_STATIC_METHOD_PARAMS(jobject, ecdhComputeSharedSecret, jobject publicKey, jobject privateKey)
{
    NH_TRY
    {
        jni.requireParameter(publicKey, "publicKey");
        jni.requireParameter(privateKey, "privateKey");
        const auto& specs = NH_SPECS();
        auto cpp_public_key = jni.fromJava<cc7::crypto::PublicKey>(specs.ecPublicKey, publicKey);
        auto cpp_private_key = jni.fromJava<cc7::crypto::PrivateKey>(specs.ecPrivateKey, privateKey);
        auto secret = algorithms().v3.ecdhWithNullKdf().phase(*cpp_private_key, *cpp_public_key);
        return CopyToSecureData(jni, secret->getKeyData());
    }
    NH_NO_THROW(nullptr)
}

//
// public static native byte[] hashSha256(byte[] data)
//
CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, hashSha256, jbyteArray data)
{
    NH_TRY
    {
        auto cpp_data = jni.fromJava(data);
        auto hash = algorithms().v3.sha256().digest(cpp_data);
        return jni.toJava(hash);
    }
    NH_NO_THROW(nullptr)
}

//
// public static native byte[] hmacSha256(byte[] data, byte[] key, int outputLength)
//
CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, hmacSha256, jbyteArray data, jbyteArray key, jint outputLength)
{
    NH_TRY
    {
        auto cpp_data = jni.fromJava(data);
        auto cpp_key = jni.fromJava(key);
        auto params = outputLength ? cc7::crypto::ParameterList {
                { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take((size_t)outputLength) }
        } : cc7::crypto::ParameterList {};
        auto cpp_result = algorithms().v3.hmacWithSha256().token(cpp_key, cpp_data, params);
        return jni.toJava(cpp_result);
    }
    NH_NO_THROW(nullptr)
}

//
// public static native byte[] randomBytes(int count);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, randomBytes, jint count)
{
    NH_TRY
    {
        if (count <= 0) {
            throw std::invalid_argument("size parameter must be greater than 0");
        }
        auto random_bytes = cc7::crypto::GetRandomData((size_t)count, true);
        return jni.toJava(random_bytes);
    }
    NH_NO_THROW(nullptr)
}

} // extern "C"
