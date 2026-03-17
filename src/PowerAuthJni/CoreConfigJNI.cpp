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
#include <PowerAuth/Configuration.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreConfig
#define CC7_JNI_CPP_CLASS           Configuration
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreConfig, thiz)

CC7_JNI_STATIC_METHOD_PARAMS(void, validateConfiguration, jstring configuration, jint algorithm)
{
    NH_TRY
    {
        auto foo = Configuration::Builder(jni.fromJava(configuration),
                                          jni.fromJava<PowerAuthSpec::Algorithm>(NH_SPECS().coreAlgorithm, algorithm));
    }
    NH_CATCH()
}

CC7_JNI_STATIC_METHOD_PARAMS(jobject, build, jstring configuration, jbyteArray deviceSpecificData, jstring instanceId, jint algorithm)
{
    NH_TRY
    {
        auto& spec = NH_SPECS();
        auto cpp_alg = jni.fromJava<PowerAuthSpec::Algorithm>(spec.coreAlgorithm, algorithm);
        auto cpp_config = Configuration::Builder(jni.fromJava(configuration), cpp_alg)
                .withInstanceId(jni.fromJava(instanceId))
                .withDeviceSpecificData(jni.fromJava(deviceSpecificData))
                .build();
        return jni.toJava(spec.coreConfig, cpp_config);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jstring, getInstanceId)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->instanceId());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jbyteArray, getDeviceSpecificData)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->deviceSpecificData());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jint, getAlgorithm)
{
    NH_TRY
    {
        auto& spec = NH_SPECS();
        auto config = jni.fromJava<Configuration>(spec.coreConfig, thiz);
        return jni.toJava(spec.coreAlgorithm, config->algorithm());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_MODULE_CLASS_END()
