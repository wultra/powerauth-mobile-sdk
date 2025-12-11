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
            JniMethod initBytes;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                { "<init>", "([B)V", offsetof(Methods, initBytes) }
        };

        struct Fields
        {
            jfieldID sensitiveData;
        };
        static constexpr JniFieldSpec fieldSpecs[1] {
                { "sensitiveData", "[B", offsetof(Fields, sensitiveData) }
        };

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    // Model
    struct ActivationCode
    {
        struct Methods
        {
            cc7::jni::JniMethod initStringString;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                { "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", offsetof(Methods, initStringString) }
        };

        struct Fields
        {
            jfieldID activationCode;
            jfieldID activationSignature;
        };
        static constexpr JniFieldSpec fieldSpecs[2] {
                { "activationCode", "Ljava/lang/String;", offsetof(Fields, activationCode) },
                { "activationSignature", "Ljava/lang/String;", offsetof(Fields, activationSignature) }
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
            cc7::jni::JniMethod init;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                // constructor: EcKeyPair(EcPrivateKey, EcPublicKey)
                { "<init>", "(Lio/getlime/security/powerauth/core/EcPrivateKey;Lio/getlime/security/powerauth/core/EcPublicKey;)V", offsetof(Methods, init) }
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };

    // Exceptions

    // io.getlime.security.powerauth.core.CoreException
    struct CoreException
    {
        struct Methods
        {
            cc7::jni::JniMethod initCodeMessageInfo;
        };
        static constexpr JniMethodSpec methodSpecs[1] = {
                // constructor: CoreException(int, String, String[])
                { "<init>", "(ILjava/lang/String;[Ljava/lang/String;)V", offsetof(Methods, initCodeMessageInfo) },
        };

        struct Fields {};
        static constexpr JniFieldSpec fieldSpecs[] {};

        jclass classRef;
        Methods methods;
        Fields fields;
    };


    EcKeyPair ecKeyPair;
    SecureData secureData;
    ActivationCode activationCode;
    CoreException coreException;

    // enums
    JniCommon::ConstantSetSpec coreErrorCode;
    JniCommon::ConstantSetSpec protocolVersion;
    // handle based objects
    JniCommon::NativeHandleClass ecPublicKey;
    JniCommon::NativeHandleClass ecPrivateKey;
    JniCommon::NativeHandleClass password;
    JniCommon::NativeHandleClass session;

    /// Build ClassSpecs structure at JNI initialization.
    static ClassSpecs buildSpecs(JNI& jni);
};


} // namespace powerAuth::jni
