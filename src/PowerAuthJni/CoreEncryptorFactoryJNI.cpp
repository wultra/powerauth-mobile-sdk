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
#include <PowerAuth/Encryptor.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreEncryptorFactory
#define CC7_JNI_CPP_CLASS           IClientEncryptorFactory
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreEncryptorFactory, thiz)

CC7_JNI_METHOD_PARAMS(jobject, createEncryptorWithScope, jint scope)
{
    NH_TRY
    {
        if (scope == 0) {
            // NONE
            throw Exception(EC_WrongParameter, "CoreEncryptorScope.None cannot be used");
        }
        auto& specs = NH_SPECS();
        auto cpp_scope = jni.fromJava<EncryptorScope>(specs.coreEncryptorScope, scope);
        auto encryptor_id = (cpp_scope == EncryptorScope::APPLICATION)
                                ? EncryptorId::APPLICATION_SCOPE_GENERIC
                                : EncryptorId::ACTIVATION_SCOPE_GENERIC;
        auto encryptor = THIS_OBJ()->getClientEncryptor(encryptor_id);
        return jni.createObject(specs.coreEncryptor.init, jni.toHandle(encryptor), scope);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, fetchTemporaryKeyForScope, jint scope)
{
    NH_TRY
    {
        if (scope == 0) {
            // NONE
            throw Exception(EC_WrongParameter, "CoreEncryptorScope.None cannot be used");
        }
        auto& specs = NH_SPECS();
        auto cpp_scope = jni.fromJava<EncryptorScope>(specs.coreEncryptorScope, scope);
        auto request = THIS_OBJ()->getTemporaryKeyRequest(cpp_scope);
        return jni::BuildCoreRequest(jni, request);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jboolean, hasPendingRequestForTemporaryKeyWithScope, jint scope)
{
    NH_TRY
    {
        if (scope != 0) {
            auto cpp_scope = jni.fromJava<EncryptorScope>(NH_SPECS().coreEncryptorScope, scope);
            return THIS_OBJ()->hasPendingTemporaryKeyRequest(cpp_scope);
        }
        return false;
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD_PARAMS(jboolean, hasTemporaryKeyForScope, jint scope)
{
    NH_TRY
    {
        if (scope != 0) {
            auto cpp_scope = jni.fromJava<EncryptorScope>(NH_SPECS().coreEncryptorScope, scope);
            return THIS_OBJ()->hasTemporaryKey(cpp_scope);
        }
        return false;
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_MODULE_CLASS_END()
