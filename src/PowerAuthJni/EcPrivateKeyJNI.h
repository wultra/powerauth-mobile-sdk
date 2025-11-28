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
#include <PowerAuth/Algorithms.h>

namespace powerAuth {
namespace jni {
    /**
     * Object that contains reference to private EC_KEY.
     */
    class EcPrivateKeyJNI {
    public:
        /**
         * Create new instance of EcPrivateKeyJNI from provided private key data. Function returns
         * nullptr if provided data doesn't represent private key.
         */
        static EcPrivateKeyJNI * createFromBytes(const cc7::ByteRange & private_key_data) {
            try {
                auto ec_key = algorithms().v3.p256().newPrivateKey(private_key_data, cc7::crypto::KEY_FORMAT_RAW);
                return new EcPrivateKeyJNI(ec_key);
            } catch (std::exception & e) {
                return nullptr;
            }
        }

        /**
         * Return private key bytes. If empty array is returned, then this object doesn't
         * have valid private key.
         */
        cc7::ByteArray privateKeyBytes() const {
            return _ec_key->exportKey(cc7::crypto::KEY_FORMAT_RAW);
        }

        /**
         * Return pointer to private key implementation.
         */
         cc7::crypto::PrivateKey & keyPtr() {
            return *_ec_key;
        }

        EcPrivateKeyJNI(const cc7::crypto::PrivateKeyPtr & ec_key) : _ec_key(ec_key) {}

    private:

        cc7::crypto::PrivateKeyPtr _ec_key;
    };
    
} // namespace jni
} // namespace powerAuth

/**
 * Get CPP object from EcPrivateKey java object.
 */
CC7_EXTERN_C powerAuth::jni::EcPrivateKeyJNI * GetEcPrivateKeyFromJavaObject(JNIEnv * env, jobject object);

/**
 * Create EcPrivateKey java object from provided CPP object. If object creation fails, then CPP object is destroyed.
 */
CC7_EXTERN_C jobject CreateJavaEcPrivateKeyFromCppObject(JNIEnv * env, powerAuth::jni::EcPrivateKeyJNI * object);
