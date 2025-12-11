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

#include <PowerAuth/Algorithms.h>
#include "NativeHelper.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          EcPrivateKey
#define CC7_JNI_CPP_CLASS           EcPrivateKeyJNI
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

// NOTE: This is a legacy interface that will be replaced with a new functionality in future SDK versions.
//       Due to a compatibility reasons, all native functions doesn't throw an exceptions.

//
// private native long init(byte[] privateKeyData)
//
CC7_JNI_STATIC_METHOD_PARAMS(jlong, initKey, jbyteArray privateKeyData)
{
    NH_TRY
    {
        auto cpp_private_key_data = jni.fromJava(privateKeyData);
        auto private_key = algorithms().v3.p256().newPrivateKey(cpp_private_key_data, cc7::crypto::KEY_FORMAT_RAW);
        return jni.toHandle(private_key);
    }
    NH_NO_THROW(0)
}

// ----------------------------------------------------------------------------
// Getters
// ----------------------------------------------------------------------------

//
// public native byte[] getKeyData(long handle)
//
CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, getKeyData, jlong handle)
{
    NH_TRY
    {
        auto private_key = jni.fromHandle<cc7::crypto::PrivateKey>(handle);
        return jni.toJava(private_key->exportKey(cc7::crypto::KEY_FORMAT_RAW));
    }
    NH_NO_THROW(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
