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
#include <PowerAuth/Task.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreTask
#define CC7_JNI_CPP_CLASS           Task
#include <cc7/jni/JniModule.inl>
#include <memory>

using namespace powerAuth;

// MARK: - Helper functions

namespace powerAuth::jni {

/// Cleanup response builder registered in the global register.
/// @param jni JNI reference.
/// @param specs ClassSpecs reference.
/// @param thiz Wrapped CoreTask java object.
/// @param builder_handle Optional response builder handle. If not provided, then handle is get from "thiz".
static void ClearResponseBuilderClosure(cc7::jni::JNI &jni, const ClassSpecs& specs, JniObject& thiz, jlong builder_handle = cc7::jni::JniObjectRegister::NULL_ID)
{
    if (cc7::jni::JNI::isNullHandle(builder_handle)) {
        builder_handle = thiz.getLong(specs.coreTask.responseBuilderHandle);
        if (cc7::jni::JNI::isNullHandle(builder_handle)) {
            // Nothing to do
            return;
        }
    }
    jni.removeHandle(builder_handle);
    thiz.setLong(specs.coreTask.responseBuilderHandle, cc7::jni::JniObjectRegister::NULL_ID);
}

jobject BuildCoreTask(cc7::jni::JNI &jni, const TaskPtr& task)
{
    return jni.toJava(NH_SPECS().coreTask.native, task);
}

jobject BuildCoreTask(cc7::jni::JNI &jni, const TaskPtr& task, const ResponseObjectBuilder & builder)
{
    auto& specs = NH_SPECS();
    // Wrap build function into auxiliary structure and register it as handle
    auto callback = std::make_shared<JavaResponseBuilder>(JavaResponseBuilder { builder });
    auto callback_handle = jni.toHandle(callback);

    // Build Request java object
    auto java_request = jni.toJava(specs.coreTask.native, task);

    // Keep build function's handle into instance of java_request.
    jni.fromJava(java_request).setLong(specs.coreTask.responseBuilderHandle, callback_handle);

    return java_request;
}

} // namespace powerAuth::jni

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreTask.native, thiz)

CC7_JNI_METHOD(jstring, getTaskName)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->name());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jboolean, isDone)
{
    NH_TRY
    {
        return THIS_OBJ()->isDone();
    }
    NH_CATCH(true)
}

CC7_JNI_METHOD(jboolean, isCanceled)
{
    NH_TRY
    {
        return THIS_OBJ()->isCanceled();
    }
    NH_CATCH(true)
}

CC7_JNI_METHOD(jboolean, isCompleted)
{
    NH_TRY
    {
        return THIS_OBJ()->isCompleted();
    }
    NH_CATCH(false)
}

CC7_JNI_METHOD(jboolean, isFailed)
{
    NH_TRY
    {
        return THIS_OBJ()->isFailed();
    }
    NH_CATCH(true)
}

CC7_JNI_METHOD(void, updateResponse)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreTask.native.classRef);
        auto this_obj = jni.fromHandle<Task>(this_wrapped.getLong(specs.coreTask.native.handle));
        // Retrieve response builder handle in advance. The value will be useful later
        auto response_builder_handle = this_wrapped.getLong(specs.coreTask.responseBuilderHandle);
        if (this_obj->isCompleted() && !this_wrapped.getBoolean(specs.coreTask.responseIsCaptured)) {
            // Task is completed and response is not captured yet.
            try {
                // Set responseIsCapture to true
                this_wrapped.setBoolean(specs.coreTask.responseIsCaptured, true);
                // Convert response JSON
                this_wrapped.setObject(specs.coreTask.responseJson, jni::JsonValueToJava(jni, this_obj->getResponseJson()));
                // Convert response object
                if (!cc7::jni::JNI::isNullHandle(response_builder_handle)) {
                    // Response builder is set, create builder reference and build a response object
                    auto builder = jni.fromHandle<jni::JavaResponseBuilder>(response_builder_handle);
                    auto response_object = builder->build(jni, specs, this_obj->getResponseObject(), this_obj->getResponseJson());
                    this_wrapped.setObject(specs.coreTask.responseObject, response_object);
                    // Unregister builder and cleanup handle
                    jni::ClearResponseBuilderClosure(jni, specs, this_wrapped, response_builder_handle);
                }
            } catch (...) {
                // Keep exception in the native object
                this_obj->setFailed(std::current_exception());
                // Cleanup builder and re-throw
                jni::ClearResponseBuilderClosure(jni, specs, this_wrapped, response_builder_handle);
                std::rethrow_exception(std::current_exception());
            }
        } else if (this_obj->isFailed() || this_obj->isCanceled()) {
            // If failed or canceled, then just release response builder.
            jni::ClearResponseBuilderClosure(jni, specs, this_wrapped, response_builder_handle);
        }
    }
    NH_CATCH()
}

CC7_JNI_METHOD(void, cancel)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreTask.native.classRef);
        auto this_obj = jni.fromHandle<Task>(this_wrapped.getLong(specs.coreTask.native.handle));
        // Cancel task
        this_obj->cancel();
        // Cleanup builder
        jni::ClearResponseBuilderClosure(jni, specs, this_wrapped);
    }
    NH_CATCH()
}

CC7_JNI_METHOD(jobject, getNextRequestImpl)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto this_wrapped = jni.fromJava(thiz, specs.coreTask.native.classRef);
        auto this_obj = jni.fromHandle<Task>(this_wrapped.getLong(specs.coreTask.native.handle));
        try {
            auto next = this_obj->getNextRequest();
            return next ? jni.toJava(specs.coreRequest.native, next) : nullptr;
        } catch (...) {
            // Keep exception in the native object
            this_obj->setFailed(std::current_exception());
            // Cleanup builder and re-throw
            jni::ClearResponseBuilderClosure(jni, specs, this_wrapped);
            std::rethrow_exception(std::current_exception());
        }
    }
    NH_CATCH(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
