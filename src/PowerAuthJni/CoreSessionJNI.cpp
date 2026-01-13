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
#include "SecureDataJNI.h"
#include <PowerAuth/Session.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreSession
#define CC7_JNI_CPP_CLASS           Session
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreSession.native, thiz)

// Construction

CC7_JNI_STATIC_METHOD_PARAMS(jobject, createSession, jobject configuration)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto cpp_config = jni.fromJava<Configuration>(specs.coreConfig, configuration);
        // Build C++ Session instance.
        auto cpp_session = Session::createInstance(cpp_config);
        // Register C++ object
        auto session_handle = jni.toHandle(cpp_session);
        // create java wrapper for time service
        auto time_service = jni.toJava(specs.coreTimeService, cpp_session->getTimeService());
        // Build final CoreSession java object
        return jni.createObject(specs.coreSession.init, session_handle, configuration, time_service);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(void, resetSession)
{
    NH_TRY
    {
        THIS_OBJ()->resetState();
    }
    NH_CATCH_RT_ONLY()
}

// Getters

CC7_JNI_METHOD(jstring, getApplicationKey)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->getConfiguration()->applicationKey());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jint, getCurrentAlgorithm)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreAlgorithm, THIS_OBJ()->getPowerAuthSpec()->algorithm());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jint, getProtocolVersion)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().protocolVersion, THIS_OBJ()->getProtocolVersion());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jboolean, canCreateActivation)
{
    NH_TRY
    {
        return THIS_OBJ()->canCreateActivation();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasPendingCreateActivation)
{
    NH_TRY
    {
        return THIS_OBJ()->hasPendingCreateActivation();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasValidActivationData)
{
    NH_TRY
    {
        return THIS_OBJ()->hasValidActivationData();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasProtocolUpgradeAvailable)
{
    NH_TRY
    {
        return THIS_OBJ()->hasProtocolUpgradeAvailable();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasPendingProtocolUpgrade)
{
    NH_TRY
    {
        return THIS_OBJ()->hasPendingProtocolUpgrade();
    }
    NH_CATCH_RT_ONLY(false)
}

// Serialization

CC7_JNI_METHOD(jbyteArray, getSerializedState)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->saveState());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(void, deserializeState, jbyteArray serializedState)
{
    NH_TRY
    {
        THIS_OBJ()->loadState(jni.fromJava(serializedState));
    }
    NH_CATCH()
}

CC7_JNI_METHOD(jboolean, isModifiedState)
{
    NH_TRY
    {
        return THIS_OBJ()->isModifiedState();
    }
    NH_CATCH_RT_ONLY(false)
}

// Activation

CC7_JNI_METHOD(jstring, getActivationIdentifier)
{
    NH_TRY
    {
        return jni.toJavaNullable(THIS_OBJ()->activationId());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jstring, getActivationFingerprint)
{
    NH_TRY
    {
        return jni.toJavaNullable(THIS_OBJ()->activationFingerprint());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

// Factor keys management

CC7_JNI_METHOD(jboolean, hasBiometryFactor)
{
    NH_TRY
    {
        return THIS_OBJ()->hasBiometricFactor();
    }
    NH_CATCH_RT_ONLY(false)
}

// Services

CC7_JNI_METHOD(jobject, getEncryptorFactory)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreEncryptorFactory, THIS_OBJ()->getEncryptorFactory());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

// Utilities

static jobject GenerateFactorKek(cc7::jni::JNI& jni, ProtocolVersion protocol_version)
{
    auto kek = cc7::crypto::GetRandomData(protocol_version == Version_V4 ? 32 : 16);
    return jni::CopyToSecureData(jni, kek);
}

CC7_JNI_METHOD(jobject, generateFactorKek)
{
    NH_TRY
    {
        return GenerateFactorKek(jni, THIS_OBJ()->getProtocolVersion());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jobject, generateFactorKekForProtocolVersion, jint protocolVersion)
{
    NH_TRY
    {
        auto version = jni.fromJava<ProtocolVersion>(NH_SPECS().protocolVersion, protocolVersion);
        return GenerateFactorKek(jni, version);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jstring, maxSupportedHttpProtocolVersion, jint protocolVersion)
{
    NH_TRY
    {
        auto version = jni.fromJava<ProtocolVersion>(NH_SPECS().protocolVersion, protocolVersion);
        return jni.toJava(ProtocolVersion_GetHttpHeaderVersion(version));
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
