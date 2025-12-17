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

#include "SecureDataJNI.h"
#include "NativeHelper.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          SecureData
#define CC7_JNI_CPP_CLASS           cc7::ByteArray
#include <cc7/jni/JniModule.inl>

namespace powerAuth::jni {

jobject CopyToSecureData(cc7::jni::JNI &jni, const cc7::ByteRange &data)
{
    const auto& specs = NH_SPECS();
    return jni.createObject(specs.secureData.methods.initBytes, jni.toJava(data));
}

jobject CopyToNullableSecureData(cc7::jni::JNI &jni, const cc7::ByteRange &data)
{
    return data.empty() ? nullptr : CopyToSecureData(jni, data);
}

cc7::ByteArray CopyFromSecureData(cc7::jni::JNI& jni, jobject object)
{
    cc7::ByteArray result;
    if (object) {
        const auto &specs = NH_SPECS();
        auto wrapped = jni.fromJava(object, specs.secureData.classRef);
        result = wrapped.getByteArray(specs.secureData.fields.sensitiveData);
    }
    return result;
}

} // namespace powerAuth::jni
