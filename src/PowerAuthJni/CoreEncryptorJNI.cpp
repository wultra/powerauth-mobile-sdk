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
#include <PowerAuth/Encryptor.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreEncryptor
#define CC7_JNI_CPP_CLASS           IClientEncryptor
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreEncryptor.native, thiz)

CC7_JNI_METHOD(jboolean , canEncryptRequest)
{
    NH_TRY
    {
        return THIS_OBJ()->canEncryptRequest();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean , canDecryptResponse)
{
    NH_TRY
    {
        return THIS_OBJ()->canDecryptResponse();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD_PARAMS(jobject, encryptRequest, jbyteArray requestBody)
{
    NH_TRY
    {
        auto& spec = NH_SPECS();
        auto encrypted = THIS_OBJ()->encryptRequest(jni.fromJava(requestBody));
        auto body = jni.toJava(cc7::json::JsonWriter::toJsonData(encrypted.requestPayload));
        auto headers = jni.createObjectArray(spec.coreHttpHeader.classRef, encrypted.requestHeaders.size());
        for (jsize index = 0; index < encrypted.requestHeaders.size(); index++) {
            const auto& cpp_header = encrypted.requestHeaders[index];
            auto header = jni.createObject(spec.coreHttpHeader.methods.init,
                                           jni.toJava(cpp_header.headerName),
                                           jni.toJava(cpp_header.headerValue));
            headers.setObject(index, header);
            header.releaseLocal();
        }
        return jni.createObject(spec.coreEncryptedRequest.methods.init, body, headers.array());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jbyteArray, decryptResponse, jobject response)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto response_body = jni.fromJava(response).getByteArray(specs.coreEncryptedResponse.fields.responseBody);
        EncryptedResponse encrypted { cc7::json::JsonReader::fromJsonData(response_body) };
        auto decrypted = THIS_OBJ()->decryptResponse(encrypted);
        return jni.toJava(decrypted);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
