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

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          NativeModule
#define CC7_JNI_CPP_CLASS           NA
#include <cc7/jni/JniModule.inl>

CC7_JNI_MODULE_CLASS_BEGIN()

//
// private native static void initializeJNI();
//
CC7_JNI_STATIC_METHOD(void, initializeJNI)
{
    powerAuth::jni::NativeHelper::registerGlobalJniInitializers();
}

CC7_JNI_MODULE_CLASS_END()
