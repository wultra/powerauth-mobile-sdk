/*
 * Copyright 2021 Wultra s.r.o.
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

#include <PowerAuth/OtpUtil.h>
#include "NativeHelper.h"

// Package: io.getlime.security.powerauth.sdk
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          ActivationCodeUtil
#define CC7_JNI_CPP_CLASS           OtpUtil
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------------

//
// public native static ActivationCode parseFromActivationCode(String activationCode)
//
CC7_JNI_STATIC_METHOD_PARAMS(jobject, parseFromActivationCode, jstring activationCode)
{
    NH_TRY
    {
        jni.requireParameter(activationCode, "activationCode");

        auto cpp_code = jni.fromJava(activationCode);
        OtpComponents components;
        if (!OtpUtil::parseActivationCode(cpp_code, components)) {
            return nullptr;
        }
        const auto& spec = NH_SPECS().activationCode;
        return jni.createObject(spec.methods.initStringString,
                                jni.toJava(components.activationCode),
                                jni.toJavaNullable(components.activationSignature));
    }
    NH_NO_THROW(nullptr)
}

// ----------------------------------------------------------------------------
// Validations
// ----------------------------------------------------------------------------

//
// public native static boolean validateTypedCharacter(int utfCodepoint)
//
CC7_JNI_STATIC_METHOD_PARAMS(jboolean, validateTypedCharacter, jint utfCodepoint)
{
    return OtpUtil::validateTypedCharacter((cc7::U32) utfCodepoint);
}

//
// public native static int validateAndCorrectTypedCharacter(int utfCodepoint)
//
CC7_JNI_STATIC_METHOD_PARAMS(jint, validateAndCorrectTypedCharacter, jint utfCodepoint)
{
    return (jint) OtpUtil::validateAndCorrectTypedCharacter((cc7::U32) utfCodepoint);
}

//
// public native static boolean validateActivationCode(String activationCode)
//
CC7_JNI_STATIC_METHOD_PARAMS(jboolean, validateActivationCode, jstring activationCode)
{
    NH_TRY
    {
        jni.requireParameter(activationCode, "activationCode");
        return OtpUtil::validateActivationCode(jni.fromJava(activationCode));
    }
    NH_NO_THROW(false)
}

CC7_JNI_MODULE_CLASS_END()
