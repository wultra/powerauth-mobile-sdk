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

#pragma once

#include <PowerAuth/Types.h>
#include <cc7/jni/JniWrapper.h>

namespace powerAuth::jni {

using namespace cc7::jni;

struct ClassSpecs
{
    // Common objects

    struct SecureData
    {
        struct Methods
        {
            JniInitMethod initBytes;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("([B)V", offsetof(Methods, initBytes))
        };

        struct Fields
        {
            jfieldID sensitiveData;
        };
        static constexpr JniFieldSpec fieldSpecs[] {
            JniFieldSpec::field("sensitiveData", "[B", offsetof(Fields, sensitiveData))
        };

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    // Model

    struct CoreHttpHeader
    {
        struct Methods
        {
            cc7::jni::JniInitMethod init;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(Ljava/lang/String;Ljava/lang/String;)V", offsetof(Methods, init))
        };

        jclass classRef;
        Methods methods;
    };

    struct CoreDevicePublicKeyData
    {
        struct Methods
        {
            cc7::jni::JniInitMethod init;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(ILjava/lang/String;[B)V", offsetof(Methods, init))
        };

        jclass classRef;
        Methods methods;
    };

    struct ActivationCode
    {
        struct Methods
        {
            cc7::jni::JniInitMethod init;
        };
        static constexpr JniMethodSpec methodSpecs[] = {
                JniMethodSpec::constructor("(Ljava/lang/String;Ljava/lang/String;)V", offsetof(Methods, init))
        };

        struct Fields
        {
            jfieldID activationCode;
            jfieldID activationSignature;
        };
        static constexpr JniFieldSpec fieldSpecs[] {
            JniFieldSpec::field("activationCode", "Ljava/lang/String;", offsetof(Fields, activationCode)),
            JniFieldSpec::field("activationSignature", "Ljava/lang/String;", offsetof(Fields, activationSignature))
        };

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    // CryptoUtils

    // io.getlime.security.powerauth.core.EcKeyPair
    struct EcKeyPair
    {
        struct Methods
        {
            cc7::jni::JniInitMethod init;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                // constructor: EcKeyPair(EcPrivateKey, EcPublicKey)
                JniMethodSpec::constructor("(Lio/getlime/security/powerauth/core/EcPrivateKey;Lio/getlime/security/powerauth/core/EcPublicKey;)V", offsetof(Methods, init))
        };

        jclass classRef;
        Methods methods;
    };

    // Exceptions

    // io.getlime.security.powerauth.core.CoreException
    struct CoreException
    {
        struct Methods
        {
            cc7::jni::JniInitMethod initCodeMessageInfo;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                // constructor: CoreException(int, String, String[])
                JniMethodSpec::constructor("(ILjava/lang/String;[Ljava/lang/String;)V", offsetof(Methods, initCodeMessageInfo))
        };

        jclass classRef;
        Methods methods;
    };

    // io.getlime.security.powerauth.core.CoreRequest
    struct CoreRequest
    {
        JniCommon::NativeHandleClass native;
        jfieldID responseBuilderHandle;
        jfieldID responseObject;
        jfieldID responseJson;
    };

    // io.getlime.security.powerauth.core.CoreTask
    struct CoreTask
    {
        JniCommon::NativeHandleClass native;
        jfieldID responseIsCaptured;
        jfieldID responseBuilderHandle;
        jfieldID responseObject;
        jfieldID responseJson;
    };

    // Deprecated?
    EcKeyPair ecKeyPair;
    JniCommon::NativeHandleClass ecPublicKey;
    JniCommon::NativeHandleClass ecPrivateKey;
    ActivationCode activationCode;

    // model
    SecureData secureData;
    CoreHttpHeader coreHttpHeader;
    CoreDevicePublicKeyData coreDevicePublicKeyData;

    // enums
    JniCommon::ConstantRangeSpec coreAlgorithm;
    JniCommon::ConstantSetSpec coreSignatureKeyId;
    JniCommon::ConstantRangeSpec coreSignatureKeyType;
    JniCommon::ConstantRangeSpec coreDevicePublicKeyFormat;
    JniCommon::ConstantSetSpec protocolVersion;
    JniCommon::ConstantRangeSpec coreEncryptorScope;

    // handle based objects
    JniCommon::NativeHandleClass password;
    JniCommon::NativeHandleClass coreConfig;
    JniCommon::NativeHandleClass coreSession;
    JniCommon::NativeHandleClass coreCredentials;
    JniCommon::NativeHandleClass coreEncryptor;
    JniCommon::NativeHandleClass coreEncryptorFactory;
    CoreRequest coreRequest;
    CoreTask coreTask;

    // exception
    JniCommon::ConstantRangeSpec coreErrorCode;
    CoreException coreException;

    /// Build ClassSpecs structure at JNI initialization.
    static ClassSpecs buildSpecs(JNI& jni);
};


} // namespace powerAuth::jni
