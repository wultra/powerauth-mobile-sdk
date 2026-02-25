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
        spec.coreCredentials = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreCredentials");
        spec.coreEncryptorFactory = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreEncryptorFactory");
        spec.coreTimeService = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreTimeService");
        // CoreSession
        spec.coreSession.native = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreSession");
        auto session = jni.fromJava(spec.coreSession.native.classRef);
        spec.coreSession.init =  { session.findMethod("<init>", "(JLio/getlime/security/powerauth/core/CoreConfig;Lio/getlime/security/powerauth/core/CoreTimeService;)V"), session };
        // CoreEncryptor
        spec.coreEncryptor.native = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreEncryptor");
        auto encryptor = jni.fromJava(spec.coreEncryptor.native.classRef);
        spec.coreEncryptor.init = { encryptor.findMethod("<init>", "(JI)V"), encryptor };
        // CoreRequest
        spec.coreRequest.native = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreRequest");
        auto request = jni.fromJava(spec.coreRequest.native.classRef);
        spec.coreRequest.initTwoHandles = { request.findMethod("<init>", "(JJ)V"), request };
        spec.coreRequest.responseBuilderHandle = request.findField("responseBuilderHandle", "J");
        spec.coreRequest.responseObject = request.findField("responseObject", "Ljava/lang/Object;");
        spec.coreRequest.responseJson = request.findField("responseJson", "Ljava/lang/Object;");
        // CoreTask
        spec.coreTask.native = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/CoreTask");
        auto task = jni.fromJava(spec.coreTask.native.classRef);
        spec.coreTask.responseIsCaptured = task.findField("responseIsCaptured", "Z");
        spec.coreTask.responseBuilderHandle = task.findField("responseBuilderHandle", "J");
        spec.coreTask.responseObject = task.findField("responseObject", "Ljava/lang/Object;");
        spec.coreTask.responseJson = task.findField("responseJson", "Ljava/lang/Object;");

        // Custom objects
        spec.secureData = jni.buildClassSpec<SecureData>("io/getlime/security/powerauth/core/SecureData");
        spec.coreHttpHeader = jni.buildClassSpec<CoreHttpHeader>("io/getlime/security/powerauth/core/CoreHttpHeader");
        spec.coreDevicePublicKeyData = jni.buildClassSpec<CoreDevicePublicKeyData>("io/getlime/security/powerauth/core/CoreDevicePublicKeyData");
        spec.coreEncryptedRequest = jni.buildClassSpec<CoreEncryptedRequest>("io/getlime/security/powerauth/core/CoreEncryptedRequest");
        spec.coreEncryptedResponse = jni.buildClassSpec<CoreEncryptedResponse>("io/getlime/security/powerauth/core/CoreEncryptedResponse");
        spec.coreFetchActivationStatusData = jni.buildClassSpec<CoreFetchActivationStatusData>("io/getlime/security/powerauth/core/CoreFetchActivationStatusData");

        // Response
        spec.respServerStatus = jni.buildClassSpec<RespServerStatus>("io/getlime/security/powerauth/core/response/CoreServerStatus");
        spec.respActivationResult = jni.buildClassSpec<RespActivationResult>("io/getlime/security/powerauth/core/response/CoreActivationResult");
        spec.respActivationStatus = jni.buildClassSpec<RespActivationStatus>("io/getlime/security/powerauth/core/response/CoreActivationStatus");
        spec.respProtocolUpgradeResult = jni.buildClassSpec<RespProtocolUpgradeResult>("io/getlime/security/powerauth/core/response/CoreProtocolUpgradeResult");
        spec.respTokenData = jni.buildClassSpec<RespTokenData>("io/getlime/security/powerauth/core/response/CoreTokenData");

        // Enums
        spec.coreProtocolVersion = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/CoreProtocolVersion", {
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
            "SPKI",
            "RAW"
        });
        spec.coreEncryptorScope = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreEncryptorScope", {
            "NONE",
            "APPLICATION",
            "ACTIVATION"
        });
        spec.coreActivationState = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreActivationState", {
            "PENDING_COMMIT",
            "ACTIVE",
            "BLOCKED",
            "REMOVED",
            "DEADLOCK"
        });
        spec.coreSecureVaultKeyId = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/CoreSecureVaultKeyId", {
           "ANY_2FA",
           "KNOWLEDGE",
           "LEGACY"
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
        jni.releaseSpec(spec.coreCredentials);
        jni.releaseSpec(spec.coreEncryptorFactory);
        jni.releaseSpec(spec.coreTimeService);
        jni.releaseSpec(spec.coreSession.native);
        jni.releaseSpec(spec.coreEncryptor.native);
        jni.releaseSpec(spec.coreRequest.native);
        jni.releaseSpec(spec.coreTask.native);
        // custom objects
        jni.releaseSpec(spec.coreHttpHeader);
        jni.releaseSpec(spec.coreDevicePublicKeyData);
        jni.releaseSpec(spec.secureData);
        jni.releaseSpec(spec.coreFetchActivationStatusData);
        // response
        jni.releaseSpec(spec.respServerStatus);
        jni.releaseSpec(spec.respActivationResult);
        jni.releaseSpec(spec.respActivationStatus);
        jni.releaseSpec(spec.respTokenData);
        // enums
        jni.releaseSpec(spec.coreProtocolVersion);
        jni.releaseSpec(spec.coreAlgorithm);
        jni.releaseSpec(spec.coreSignatureKeyId);
        jni.releaseSpec(spec.coreSignatureKeyType);
        jni.releaseSpec(spec.coreDevicePublicKeyFormat);
        jni.releaseSpec(spec.coreEncryptorScope);
        jni.releaseSpec(spec.coreActivationState);
        jni.releaseSpec(spec.coreSecureVaultKeyId);
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
