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

#include "NativeHelper.h"
#include <PowerAuth/Algorithms.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          EcPublicKey
#define CC7_JNI_CPP_CLASS           cc7::crypto::PublicKey
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

//
// private native static long initKey(@NonNull byte[] publicKeyData)
//
CC7_JNI_STATIC_METHOD_PARAMS(jlong, initKey, jbyteArray publicKeyData)
{
    NH_TRY
    {
        jni.requireParameter(publicKeyData, "publicKeyData");
        auto cpp_public_key_data = jni.fromJava(publicKeyData);
        auto private_key = algorithms().v3.p256().newPublicKey(cpp_public_key_data, cc7::crypto::KEY_FORMAT_X963);
        return jni.toHandle(private_key);
    }
    NH_CATCH(0)
}

//
// private native static byte[] getKeyData(long handle)
//
CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, getKeyData, jlong handle)
{
    NH_TRY
    {
        auto public_key = jni.fromHandle<cc7::crypto::PublicKey>(handle);
        return jni.toJava(public_key->exportKey(cc7::crypto::KEY_FORMAT_X963));
    }
    NH_CATCH(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
