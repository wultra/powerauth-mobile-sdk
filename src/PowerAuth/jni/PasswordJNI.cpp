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

#include "PasswordJNI.h"
#include <algorithm>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          Password
#define CC7_JNI_CPP_CLASS           Password
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

Password * GetCppPasswordFromJavaObject(JNIEnv * env, jobject passwordObject)
{
    if (!env || !passwordObject) {
        CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
        return NULL;
    }
    auto cppPass = reinterpret_cast<Password*>(env->GetLongField(passwordObject, GetHandleFieldID(env)));
    if (!cppPass) {
        CC7_ASSERT(false, "Unable to get C++ object from 'Password' java object.");
        return NULL;
    }
    return cppPass;
}

// ----------------------------------------------------------------------------
// Init & Destroy
// ----------------------------------------------------------------------------

//
// private native long initPassword(String strPass, byte[] dataPass)
//
CC7_JNI_METHOD_PARAMS(jlong, initPassword, jstring strPass, jbyteArray dataPass)
{
    auto pass = new Password();
    if (strPass != NULL && dataPass == NULL) {
        // initialize immutable password with string
        auto cppData = cc7::jni::CopyFromJavaStringToByteArray(env, strPass);
        pass->initAsImmutable(cppData);
        //
    } else if (strPass == NULL && dataPass != NULL) {
        // initialize immutable password with byte array
        auto cppData = cc7::jni::CopyFromJavaByteArray(env, dataPass);
        pass->initAsImmutable(cppData);
        //
    } else if (strPass == NULL && dataPass == NULL) {
        // initialize mutable empty password
        pass->initAsMutable();
        //
    } else {
        CC7_ASSERT(false, "Invalid combination of parameters.");
        delete pass;
        return 0;
    }
    return (jlong)pass;
}

//
// private native void destroy(long handle)
//
CC7_JNI_METHOD_PARAMS(void, destroy, jlong handle)
{
    auto pass = CC7_THIS_OBJ();
    if (!pass || (jlong)pass != handle) {
        CC7_ASSERT(false, "Internal object is already destroyed, or provided handle is not ours.");
        return;
    }
    delete pass;
}

// ----------------------------------------------------------------------------
// Methods for immutable operations
// ----------------------------------------------------------------------------

//
// public native boolean isMutable();
//
CC7_JNI_METHOD(jboolean, isMutable)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->isMutable() : false;
}

//
// public native int length();
//
CC7_JNI_METHOD(jint, length)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? (jint)pass->length() : 0; 
}

//
// public native boolean isEqualToPassword(Password anotherPassword)
//
CC7_JNI_METHOD_PARAMS(jboolean, isEqualToPassword, jobject anotherPassword)
{
    auto pass = CC7_THIS_OBJ();
    if (!pass || !anotherPassword) {
        return false;
    }
    auto otherPass = GetCppPasswordFromJavaObject(env, anotherPassword);
    if (!otherPass) {
        return false;
    }
    return pass->isEqualToPassword(*otherPass);
}

// ----------------------------------------------------------------------------
// Methods for mutable operations
// ----------------------------------------------------------------------------

//
// public native boolean clear()
//
CC7_JNI_METHOD(jboolean, clear)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->clear() : false;
}

//
// public native boolean addCharacter(int utfCodepoint)
//
CC7_JNI_METHOD_PARAMS(jboolean, addCharacter, jint utfCodepoint)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->addCharacter((cc7::U32)utfCodepoint) : false;
}

//
// public native boolean insertCharacter(int utfCodepoint, int index)
//
CC7_JNI_METHOD_PARAMS(jboolean, insertCharacter, jint utfCodepoint, jint index)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->insertCharacter((cc7::U32)utfCodepoint, (size_t)index) : false;
}

//
// public native boolean removeLastCharacter()
//
CC7_JNI_METHOD(jboolean, removeLastCharacter)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->removeLastCharacter() : false;
}

//
// public native boolean removeCharacter(int index)
//
CC7_JNI_METHOD_PARAMS(jboolean, removeCharacter, jint index)
{
    auto pass = CC7_THIS_OBJ();
    return pass ? pass->removeCharacter((size_t)index) : false;
}

//
// private native byte[] getPlaintextPassword();
//
CC7_JNI_METHOD(jbyteArray , getPlaintextPassword)
{
	auto pass = CC7_THIS_OBJ();
	return pass ? cc7::jni::CopyToJavaByteArray(env, pass->passwordData()) : nullptr;
}

CC7_JNI_MODULE_CLASS_END()
