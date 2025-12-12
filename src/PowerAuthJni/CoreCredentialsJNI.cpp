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

#include "NativeHelper.h"
#include <PowerAuth/Credentials.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreCredentials
#define CC7_JNI_CPP_CLASS           Credentials
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreConfig, thiz)

CC7_JNI_STATIC_METHOD(jobject, possession)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreCredentials, Credentials::possession());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jobject, knowledge, jobject password)
{
    NH_TRY
    {
        auto& spec = NH_SPECS();
        auto cpp_password = jni.fromJava<Password>(spec.password, password);
        return jni.toJava(spec.coreCredentials, Credentials::knowledge(cpp_password->passwordData()));
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jobject, biometry, jobject secureData)
{
    NH_TRY
    {
        auto cpp_data = jni::CopyFromSecureData(jni, secureData);
        return jni.toJava(NH_SPECS().coreCredentials, Credentials::knowledge(cpp_data));
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
