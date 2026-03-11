/*
 * Copyright 2016-2017 Wultra s.r.o.
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
#include <PowerAuth/Password.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          Password
#define CC7_JNI_CPP_CLASS           Password
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<Password>(NH_SPECS().password, thiz)

CC7_JNI_STATIC_METHOD_PARAMS(jlong, initPassword, jstring strPass, jbyteArray dataPass, jlong handleOtherPassword)
{
    NH_TRY
    {
        auto pass = std::make_shared<Password>();
        auto has_str = strPass != nullptr;
        auto has_data = dataPass != nullptr;
        auto has_other = !cc7::jni::JNI::isNullHandle(handleOtherPassword);

        if ((has_str && has_data) || (has_str && has_other) || (has_data && has_other)) {
            throw std::invalid_argument("Invalid combination of input parameters");
        }

        if (has_str) {
            // initialize immutable password with string
            pass->initAsImmutable(jni.fromJavaStringToBytes(strPass));
            //
        } else if (has_data) {
            // initialize immutable password with byte array
            pass->initAsImmutable(jni.fromJava(dataPass));
        } else if (has_other) {
            // Initialize as copy from another password
            auto otherPass = jni.fromHandle<Password>(handleOtherPassword);
            pass->initAsImmutable(otherPass->passwordData());
        } else {
            // otherwise initialize mutable empty password
            pass->initAsMutable();
        }
        return jni.toHandle(pass);
    }
    NH_CATCH(0)
}

// ----------------------------------------------------------------------------
// Methods for immutable operations
// ----------------------------------------------------------------------------

CC7_JNI_METHOD(jboolean, isMutable)
{
    NH_TRY
    {
        return THIS_OBJ()->isMutable();
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD(jint, length)
{
    NH_TRY
    {
        return (jint) THIS_OBJ()->length();
    }
    NH_CATCH(0)
}

CC7_JNI_STATIC_METHOD_PARAMS(jboolean, isEqualToPassword, jlong handle, jlong handleAnotherPassword)
{
    NH_TRY
    {
        auto thisPassword = jni.fromHandle<Password>(handle);
        auto otherPassword = jni.fromHandle<Password>(handleAnotherPassword);
        return thisPassword->isEqualToPassword(*otherPassword);
    }
    NH_CATCH(false)
}

// ----------------------------------------------------------------------------
// Methods for mutable operations
// ----------------------------------------------------------------------------

CC7_JNI_METHOD(jboolean, clear)
{
    NH_TRY
    {
        return THIS_OBJ()->clear();
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD_PARAMS(jboolean, addCharacter, jint utfCodepoint)
{
    NH_TRY
    {
        return THIS_OBJ()->addCharacter((cc7::U32)utfCodepoint);
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD_PARAMS(jboolean, insertCharacter,jint utfCodepoint, jint index)
{
    NH_TRY
    {
        return THIS_OBJ()->insertCharacter((cc7::U32)utfCodepoint, (size_t)index);
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD(jboolean, removeLastCharacter)
{
    NH_TRY
    {
        return THIS_OBJ()->removeLastCharacter();
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD_PARAMS(jboolean, removeCharacter, jint index)
{
    NH_TRY
    {
        return THIS_OBJ()->removeCharacter((size_t)index);
    }
    NH_CATCH(false)
}

CC7_JNI_STATIC_METHOD_PARAMS(jbyteArray, getPlaintextPassword, jlong handle)
{
    NH_TRY
    {
        auto pass = jni.fromHandle<Password>(handle);
        return jni.toJava(pass->passwordData());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
