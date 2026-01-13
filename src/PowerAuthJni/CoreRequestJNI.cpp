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

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreRequest
#define CC7_JNI_CPP_CLASS           Request
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;


// MARK: - Helper functions

namespace powerAuth::jni {

/// Cleanup response builder registered in the global register.
/// @param jni JNI reference.
/// @param specs ClassSpecs reference.
/// @param thiz Wrapped CoreRequest java object.
/// @param builder_handle Optional response builder handle. If not provided, then handle is get from "thiz".
static void ClearResponseBuilderClosure(cc7::jni::JNI &jni, const ClassSpecs& specs, JniObject& thiz, jlong builder_handle = cc7::jni::JniObjectRegister::NULL_ID)
{
    if (cc7::jni::JNI::isNullHandle(builder_handle)) {
        builder_handle = thiz.getLong(specs.coreRequest.responseBuilderHandle);
        if (cc7::jni::JNI::isNullHandle(builder_handle)) {
            // Nothing to do
            return;
        }
    }
    jni.removeHandle(builder_handle);
    thiz.setLong(specs.coreRequest.responseBuilderHandle, cc7::jni::JniObjectRegister::NULL_ID);
}

jobject BuildCoreRequest(cc7::jni::JNI &jni, const RequestPtr& request)
{
    return jni.toJava(NH_SPECS().coreRequest.native, request);
}

jobject BuildCoreRequest(cc7::jni::JNI &jni, const RequestPtr& request, const ResponseObjectBuilder & builder)
{
    auto& specs = NH_SPECS();
    // Wrap build function into auxiliary structure and register it as handle
    auto callback = std::make_shared<JavaResponseBuilder>(JavaResponseBuilder { builder });
    auto callback_handle = jni.toHandle(callback);

    // Build Request java object
    auto java_request = jni.toJava(specs.coreRequest.native, request);

    // Keep build function's handle into instance of java_request.
    jni.fromJava(java_request).setLong(specs.coreRequest.responseBuilderHandle, callback_handle);

    return java_request;
}

} // namespace powerAuth::jni


CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreRequest.native, thiz)

CC7_JNI_METHOD(jboolean, isRequireSynchronizedTime)
{
    NH_TRY
    {
        return THIS_OBJ()->requireSynchronizedTime();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, isRequireSerialQueue)
{
    NH_TRY
    {
        return THIS_OBJ()->requireSerialQueue();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, isAllowedInUpgrade)
{
    NH_TRY
    {
        return THIS_OBJ()->isAllowedInUpgrade();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jint, getEncryptorScope)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_obj = jni.fromJava<Request>(specs.coreRequest.native, thiz);
        if (this_obj->isEncrypted()) {
            return jni.toJava(specs.coreEncryptorScope, this_obj->encryptorScope());
        }
        return specs.coreEncryptorScope.bottomValue; // NONE
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jboolean, isAuthenticated)
{
    NH_TRY
    {
        return THIS_OBJ()->isAuthenticated();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jstring, getRelativePath)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->getRelativePath());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jstring, getHttpMethod)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->getHttpMethod());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jbyteArray, getRequestBody)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->getRequestBody());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jobjectArray , getRequestHeaders)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto headers = jni.fromJava<Request>(specs.coreRequest.native, thiz)->getRequestHeaders();
        auto result = jni.createObjectArray(specs.coreHttpHeader.classRef, headers.size());
        for (auto index = 0; index < headers.size(); index++) {
            auto java_header = jni.createObject(specs.coreHttpHeader.methods.init,
                                                jni.toJava(headers[index].headerName),
                                                jni.toJava(headers[index].headerValue));
            result.setObject(index, java_header);
        }
        return result;
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jboolean, isDone)
{
    NH_TRY
    {
        return THIS_OBJ()->isDone();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, isCompleted)
{
    NH_TRY
    {
        return THIS_OBJ()->isCompleted();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, isCanceled)
{
    NH_TRY
    {
        return THIS_OBJ()->isCanceled();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, isFailed)
{
    NH_TRY
    {
        return THIS_OBJ()->isFailed();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(void, cancel)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreRequest.native.classRef);
        auto this_obj = jni.fromHandle<Request>(this_wrapped.getLong(specs.coreRequest.native.handle));
        // cancel object
        this_obj->cancel();
        // cleanup builder
        jni::ClearResponseBuilderClosure(jni, specs, this_wrapped);
    }
    NH_CATCH_RT_ONLY()
}

CC7_JNI_METHOD(void, setFailed)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreRequest.native.classRef);
        auto this_obj = jni.fromHandle<Request>(this_wrapped.getLong(specs.coreRequest.native.handle));
        // set failed
        this_obj->setFailed(nullptr);
        // cleanup builder
        jni::ClearResponseBuilderClosure(jni, specs, this_wrapped);
    }
    NH_CATCH_RT_ONLY()
}

CC7_JNI_METHOD(void, prepareRequestImpl)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreRequest.native.classRef);
        auto this_obj = jni.fromHandle<Request>(this_wrapped.getLong(specs.coreRequest.native.handle));
        try {
            this_obj->prepareRequest();
        } catch (...) {
            // Cleanup builder and re-throw
            jni::ClearResponseBuilderClosure(jni, specs, this_wrapped);
            std::rethrow_exception(std::current_exception());
        }
    }
    NH_CATCH()
}

CC7_JNI_METHOD_PARAMS(void, processResponseImpl, jbyteArray response)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreRequest.native.classRef);
        auto this_obj = jni.fromHandle<Request>(this_wrapped.getLong(specs.coreRequest.native.handle));
        auto response_builder_handle = this_wrapped.getLong(specs.coreRequest.responseBuilderHandle);

        try {
            // Process response
            this_obj->processResponse(jni.fromJava(response));

            if (!cc7::jni::JNI::isNullHandle(response_builder_handle)) {
                // Java response construction build is specified.
                auto callback = jni.fromHandle<jni::JavaResponseBuilder>(response_builder_handle);
                auto response_object = callback->build(jni, specs, this_obj->getResponseObject(), this_obj->getResponseJson());
                // Keep response object in Request instance
                this_wrapped.setObject(specs.coreRequest.responseObject, response_object);
                // Cleanup builder
                jni::ClearResponseBuilderClosure(jni, specs, this_wrapped, response_builder_handle);
            }
            if (this_obj->isPublicResponseJson()) {
                // Convert response JSON to generic object hierarchy
                auto response_json = cc7::jni::JsonValueToJava(jni, this_obj->getResponseJson());
                // Keep response JSON in Request instance
                this_wrapped.setObject(specs.coreRequest.responseJson, response_json);
            }
        } catch (...) {
            // Cleanup builder in case of failure
            jni::ClearResponseBuilderClosure(jni, specs, this_wrapped, response_builder_handle);
            // Rethrow exception
            std::rethrow_exception(std::current_exception());
        }
    }
    NH_CATCH()
}

CC7_JNI_MODULE_CLASS_END()
