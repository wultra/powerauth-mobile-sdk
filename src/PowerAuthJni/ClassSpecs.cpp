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
        // Handle based objects
        spec.password = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/Password");
        spec.session = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/Session");
        spec.ecPublicKey = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/EcPublicKey");
        spec.ecPrivateKey = jni.buildNativeHandleSpec("io/getlime/security/powerauth/core/EcPrivateKey");
        // Custom objects
        spec.ecKeyPair = jni.buildClassSpec<EcKeyPair>("io/getlime/security/powerauth/core/EcKeyPair");
        spec.secureData = jni.buildClassSpec<SecureData>("io/getlime/security/powerauth/core/SecureData");
        spec.activationCode = jni.buildClassSpec<ActivationCode>("io/getlime/security/powerauth/core/ActivationCode");
        // Enums
        spec.powerAuthAlgorithm = jni.buildConstantRangeSpec("io/getlime/security/powerauth/core/Algorithm", {
            "LEGACY_P256",
            "EC_P384",
            "EC_P384_ML_L3",
            "EC_P384_ML_L5"
        });
        spec.protocolVersion = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/ProtocolVersion", {
            "NA",
            "V2",
            "V3",
            "V4"
        });
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
        // Exceptions
        spec.coreException = jni.buildClassSpec<CoreException>("io/getlime/security/powerauth/core/CoreException");
    } catch (...) {
        // Cleanup already resolved classes
        jni.releaseSpec(spec.password);
        jni.releaseSpec(spec.session);
        jni.releaseSpec(spec.ecPublicKey);
        jni.releaseSpec(spec.ecPrivateKey);
        jni.releaseSpec(spec.ecKeyPair);
        jni.releaseSpec(spec.secureData);
        jni.releaseSpec(spec.activationCode);
        jni.releaseSpec(spec.protocolVersion);
        jni.releaseSpec(spec.coreErrorCode);
        jni.releaseSpec(spec.coreException);
        // rethrow the exception
        std::rethrow_exception(std::current_exception());
    }
    return spec;
}

} // namespace powerAuth::jni
