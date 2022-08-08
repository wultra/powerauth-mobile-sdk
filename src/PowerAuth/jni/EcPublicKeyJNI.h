/*
 * Copyright 2022 Wultra s.r.o.
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

#include <cc7/jni/JniHelper.h>
#include <PowerAuth/crypto/ECC.h>
#include <openssl/ec.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace jni
{
    /**
     * Object that contains reference to public EC_KEY.
     */
    class EcPublicKeyJNI {
    public:
        /**
         * Create new instance of EcPrivateKeyJNI from provided private key data. Function returns
         * nullptr if provided data doesn't represent private key.
         */
        static EcPublicKeyJNI * createFromBytes(const cc7::ByteRange & public_key_data, BN_CTX * ctx = nullptr) {
            auto ec_key = crypto::ECC_ImportPublicKey(nullptr, public_key_data, ctx);
            return ec_key != nullptr ? new EcPublicKeyJNI(ec_key) : nullptr;
        }

        ~EcPublicKeyJNI() {
            EC_KEY_free(ec_key);
        }

        /**
         * Return public key bytes. If empty array is returned, then this object doesn't
         * have valid public key.
         */
        cc7::ByteArray publicKeyBytes() const {
            return crypto::ECC_ExportPublicKey(ec_key);
        }

        /**
         * Return pointer to public key implementation.
         */
        EC_KEY * keyPtr() const {
            return ec_key;
        }

    private:

        EcPublicKeyJNI(EC_KEY * ec_key) : ec_key(ec_key) {}

        EC_KEY * ec_key;
    };
    
} // io::getlime::powerAuth::jni
} // io::getlime::powerAuth
} // io::getlime
} // io

/**
 * Get CPP object from EcPublicKey java object.
 */
CC7_EXTERN_C io::getlime::powerAuth::jni::EcPublicKeyJNI * GetEcPublicKeyFromJavaObject(JNIEnv * env, jobject object);

/**
 * Create EcPublicKey java object from provided CPP object. If object creation fails, then CPP object is destroyed.
 */
CC7_EXTERN_C jobject CreateJavaEcPublicKeyFromCppObject(JNIEnv * env, io::getlime::powerAuth::jni::EcPublicKeyJNI * object);
