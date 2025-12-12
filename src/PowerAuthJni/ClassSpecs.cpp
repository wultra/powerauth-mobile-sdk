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

#include "ClassSpecs.h"

namespace powerAuth::jni {

ClassSpecs ClassSpecs::buildSpecs(JNI &jni)
{
    ClassSpecs spec {};
    try {
        // Resolve all objects used in JNI wrapper

        // Handle based objects
        spec.password = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/Password");
        spec.coreConfig = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreConfig");
        spec.coreSession = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreSession");
        spec.coreCredentials = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreCredentials");
        spec.coreEncryptor = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreEncryptor");
        spec.coreEncryptorFactory = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreEncryptorFactory");
        spec.coreRequest = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreRequest");
        spec.coreTask = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreTask");

        // Custom objects
        spec.secureData = jni.buildClassSpec<SecureData>("io/getlime/security/powerauth/core/SecureData");
        spec.coreHttpHeader = jni.buildClassSpec<CoreHttpHeader>("io/getlime/security/powerauth/core/CoreHttpHeader");
        spec.coreDevicePublicKeyData = jni.buildClassSpec<CoreDevicePublicKeyData>("io/getlime/security/powerauth/core/CoreDevicePublicKeyData");

        // Enums
        spec.protocolVersion = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/ProtocolVersion", {
            "NA",
            "V2",
            "V3",
            "V4"
        });
        spec.coreAlgorithm = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreAlgorithm", {
            "LEGACY_P256",
            "EC_P384",
            "EC_P384_ML_L3",
            "EC_P384_ML_L5"
        });
        spec.coreSignatureKeyId = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/CoreSignatureKeyId", {
            "MASTER",
            "MASTER_EC",
            "MASTER_ML_DSA",
            "SERVER",
            "SERVER_EC",
            "SERVER_ML_DSA",
            "DEVICE",
            "DEVICE_EC",
            "DEVICE_ML_DSA",
            "MAC_PERSONALIZED"
        });
        spec.coreSignatureKeyType = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreSignatureKeyType", {
            "EC",
            "ML_DSA"
        });
        spec.coreDevicePublicKeyFormat = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreDevicePublicKeyFormat", {
            "DER",
            "RAW"
        });
        spec.coreEncryptorScope = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreEncryptorScope", {
            "NONE",
            "APPLICATION",
            "ACTIVATION"
        });

        // Exceptions
        spec.coreErrorCode = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreErrorCode", {
            "MISSING_ACTIVATION",
            "WRONG_ACTIVATION_STATE",
            "WRONG_PARAMETER",
            "BIOMETRY_NOT_ALLOWED",
            "NOT_ALLOWED",
            "TIME_NOT_SYNCHRONIZED",
            "INVALID_DATA",
            "INVALID_RESPONSE",
            "WRONG_SIGNATURE",
            "INTERNAL_ERROR",
            "CRYPTOGRAPHY",
            "CANCELED",
            "PENDING_PROTOCOL_UPGRADE",
            "OTHER"
        });
        spec.coreException = jni.buildClassSpec<CoreException>("io/getlime/security/powerauth/core/CoreException");

        // Deprecated
        spec.ecKeyPair = jni.buildClassSpec<EcKeyPair>("io/getlime/security/powerauth/core/EcKeyPair");
        spec.ecPublicKey = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/EcPublicKey");
        spec.ecPrivateKey = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/EcPrivateKey");
        spec.activationCode = jni.buildClassSpec<ActivationCode>("io/getlime/security/powerauth/core/ActivationCode");

    } catch (...) {
        // Cleanup already resolved classes
        // handle based
        jni.releaseSpec(spec.password);
        jni.releaseSpec(spec.coreConfig);
        jni.releaseSpec(spec.coreSession);
        jni.releaseSpec(spec.coreCredentials);
        jni.releaseSpec(spec.coreEncryptor);
        jni.releaseSpec(spec.coreEncryptorFactory);
        jni.releaseSpec(spec.coreRequest);
        jni.releaseSpec(spec.coreTask);
        // custom objects
        jni.releaseSpec(spec.coreHttpHeader);
        jni.releaseSpec(spec.coreDevicePublicKeyData);
        jni.releaseSpec(spec.secureData);
        // enums
        jni.releaseSpec(spec.protocolVersion);
        jni.releaseSpec(spec.coreAlgorithm);
        jni.releaseSpec(spec.coreSignatureKeyId);
        jni.releaseSpec(spec.coreSignatureKeyType);
        jni.releaseSpec(spec.coreDevicePublicKeyFormat);
        jni.releaseSpec(spec.coreEncryptorScope);
        // exception
        jni.releaseSpec(spec.coreErrorCode);
        jni.releaseSpec(spec.coreException);
        // deprecated
        jni.releaseSpec(spec.ecKeyPair);
        jni.releaseSpec(spec.ecPublicKey);
        jni.releaseSpec(spec.ecPrivateKey);
        jni.releaseSpec(spec.activationCode);
        // rethrow the exception
        std::rethrow_exception(std::current_exception());
    }
    return spec;
}

} // namespace powerAuth::jni
