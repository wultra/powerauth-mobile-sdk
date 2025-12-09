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
        spec.password = jni.buildClassSpec<JniCommon::NativeHandleClass>("io/getlime/security/powerauth/core/Password");
        spec.session = jni.buildClassSpec<JniCommon::NativeHandleClass>("io/getlime/security/powerauth/core/Session");
        spec.ecPublicKey = jni.buildClassSpec<JniCommon::NativeHandleClass>("io/getlime/security/powerauth/core/EcPublicKey");
        spec.ecPrivateKey = jni.buildClassSpec<JniCommon::NativeHandleClass>("io/getlime/security/powerauth/core/EcPrivateKey");
        // Custom objects
        spec.ecKeyPair = jni.buildClassSpec<EcKeyPair>("io/getlime/security/powerauth/core/EcKeyPair");
        spec.secureData = jni.buildClassSpec<SecureData>("io/getlime/security/powerauth/core/SecureData");
        spec.activationCode = jni.buildClassSpec<ActivationCode>("io/getlime/security/powerauth/core/ActivationCode");
        spec.protocolVersion = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/ProtocolVersion", {
            "NA",
            "V2",
            "V3",
            "V4"
        });
        spec.coreErrorCode = jni.buildConstantSetSpec("io/getlime/security/powerauth/core/CoreErrorCode", {
            "MISSING_ACTIVATION",
            "WRONG_ACTIVATION_STATE",
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
    } catch (...) {
        // Cleanup already resolved classes
        jni.releaseObject(spec.password.classRef);
        jni.releaseObject(spec.session.classRef);
        jni.releaseObject(spec.ecPublicKey.classRef);
        jni.releaseObject(spec.ecPrivateKey.classRef);
        jni.releaseObject(spec.ecKeyPair.classRef);
        jni.releaseObject(spec.secureData.classRef);
        jni.releaseObject(spec.activationCode.classRef);
        jni.releaseObject(spec.protocolVersion.classRef);
        jni.releaseObject(spec.coreErrorCode.classRef);
        jni.releaseObject(spec.coreException.classRef);
        // rethrow the exception
        std::rethrow_exception(std::current_exception());
    }
    return spec;
}

} // namespace powerAuth::jni
