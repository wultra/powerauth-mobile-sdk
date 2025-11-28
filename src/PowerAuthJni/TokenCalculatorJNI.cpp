/*
 * Copyright 2017 Wultra s.r.o.
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

#include <PowerAuth/Types.h>
#include <PowerAuth/Algorithms.h>
#include <cc7/jni/JniHelper.h>
#include <sys/time.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          TokenCalculator
#define CC7_JNI_CPP_CLASS           NA
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

extern "C" {

//
// public static native String calculateTokenValue(PowerAuthPrivateTokenData tokenData, long timestamp)
//
CC7_JNI_METHOD_PARAMS(jstring, calculateTokenValue, jobject privateData, jlong timestamp)
{
    return nullptr;
}

} // extern "C"
