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

#include "EcPrivateKeyJNI.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          EcPrivateKey
#define CC7_JNI_CPP_CLASS           EcPrivateKeyJNI
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;
using namespace io::getlime::powerAuth::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Init & Destroy
// ----------------------------------------------------------------------------

//
// private native void destroy(long handle)
//
CC7_JNI_METHOD_PARAMS(void, destroy, jlong handle)
{
    auto object = CC7_THIS_OBJ();
    if (!object || (jlong)object != handle) {
        CC7_ASSERT(false, "Internal object is already destroyed, or provided handle is not ours.");
        return;
    }
    delete object;
}

//
// private native long init(byte[] privateKeyData)
//
CC7_JNI_METHOD_PARAMS(jlong, init, jbyteArray privateKeyData)
{
    auto cppPrivateKeyData = cc7::jni::CopyFromJavaByteArray(env, privateKeyData);
    auto object = EcPrivateKeyJNI::createFromBytes(cppPrivateKeyData);
    return object != nullptr ? reinterpret_cast<jlong>(object) : 0;
}

// ----------------------------------------------------------------------------
// Getters
// ----------------------------------------------------------------------------

//
// public native byte[] getPrivateKeyData()
//
CC7_JNI_METHOD(jbyteArray, getPrivateKeyData)
{
    auto object = CC7_THIS_OBJ();
    if (!object) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    return cc7::jni::CopyToNullableJavaByteArray(env, object->privateKeyBytes());
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

EcPrivateKeyJNI * GetEcPrivateKeyFromJavaObject(JNIEnv * env, jobject thiz)
{
    auto object = CC7_THIS_OBJ();
    return object;
}

jobject CreateJavaEcPrivateKeyFromCppObject(JNIEnv * env, EcPrivateKeyJNI * object)
{
    if (!env || !object) {
        CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
        delete object;
        return nullptr;
    }
    auto object_ptr_long = reinterpret_cast<jlong>(object);
    jobject java_object = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("EcPrivateKey"), "(J)V", object_ptr_long);
    if (nullptr == java_object) {
        delete object;
    }
    return java_object;
}

CC7_JNI_MODULE_CLASS_END()
