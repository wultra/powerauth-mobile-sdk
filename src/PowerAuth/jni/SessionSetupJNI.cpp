/*
 * Copyright 2023 Wultra s.r.o.
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

#include <PowerAuth/Session.h>
#include <cc7/jni/JniHelper.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          SessionSetup
#define CC7_JNI_CPP_CLASS           SessionSetup
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

//
// public static native boolean validateConfiguration(String configuration)
//
CC7_JNI_METHOD_PARAMS(jboolean, validateConfiguration, jstring configuration)
{
    SessionSetup cppSetup;
    return cppSetup.loadFromConfiguration(cc7::jni::CopyFromJavaString(env, configuration));
}

CC7_JNI_MODULE_CLASS_END()
