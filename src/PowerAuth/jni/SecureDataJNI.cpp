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

 #include "SecureDataJNI.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          SecureData
#define CC7_JNI_CPP_CLASS           SecureData
#include <cc7/jni/JniModule.inl>

 using namespace io::getlime::powerAuth;

jobject CopyToSecureData(JNIEnv * env, const cc7::ByteRange & data)
{
    auto secure_data_class = CC7_JNI_MODULE_FIND_CLASS("SecureData");
    if (!secure_data_class) {
        return nullptr;
    }
    // static SecureData capture(byte[] param);
    const auto method_signature = "([B)" CC7_JNI_MODULE_CLASS_SIGNATURE("SecureData");
    auto method_id = env->GetStaticMethodID(secure_data_class, "capture", method_signature);
    if (!method_id) {
        return nullptr;
    }
    auto array = cc7::jni::CopyToJavaByteArray(env, data);
    return env->CallStaticObjectMethod(secure_data_class, method_id, array);
}

jobject CopyToNullableSecureData(JNIEnv * env, const cc7::ByteRange & data)
{
    return data.empty() ? nullptr : CopyToSecureData(env, data);
}

cc7::ByteArray CopyFromSecureData(JNIEnv * env, jobject object)
{
    cc7::ByteArray result;
    if (object) {
        auto secure_data_class = CC7_JNI_MODULE_FIND_CLASS("SecureData");
        if (secure_data_class) {
            result = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(object, secure_data_class, "sensitiveData"));
        }
    }
    return result;
}
