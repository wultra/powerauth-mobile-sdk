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
     * Object that contains reference to public EC_KEY.
     */
    class EcPublicKeyJNI {
    public:
        /**
         * Create new instance of EcPrivateKeyJNI from provided private key data. Function returns
         * nullptr if provided data doesn't represent private key.
         */
        static EcPublicKeyJNI *createFromBytes(const cc7::ByteRange &public_key_data) {
            try {
                auto ec_key = algorithms().v3.p256().newPublicKey(public_key_data,
                                                               cc7::crypto::KEY_FORMAT_X963);
                return new EcPublicKeyJNI(ec_key);
            } catch (std::exception &e) {
                return nullptr;
            }
        }

        /**
         * Return public key bytes. If empty array is returned, then this object doesn't
         * have valid public key.
         */
        cc7::ByteArray publicKeyBytes() const {
            return _ec_key->exportKey(cc7::crypto::KEY_FORMAT_X963);
        }

        /**
         * Return pointer to public key implementation.
         */
        cc7::crypto::PublicKey &keyPtr() {
            return *_ec_key;
        }

        EcPublicKeyJNI(const cc7::crypto::PublicKeyPtr &ec_key) : _ec_key(ec_key) {}

    private:

        cc7::crypto::PublicKeyPtr _ec_key;
    };

} // namespace jni
} // namespace powerAuth


/**
 * Get CPP object from EcPublicKey java object.
 */
CC7_EXTERN_C powerAuth::jni::EcPublicKeyJNI * GetEcPublicKeyFromJavaObject(JNIEnv * env, jobject object);

/**
 * Create EcPublicKey java object from provided CPP object. If object creation fails, then CPP object is destroyed.
 */
CC7_EXTERN_C jobject CreateJavaEcPublicKeyFromCppObject(JNIEnv * env, powerAuth::jni::EcPublicKeyJNI * object);
