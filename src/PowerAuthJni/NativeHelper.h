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

#include "ClassSpecs.h"
#include "SecureDataJNI.h"
#include <PowerAuth/Task.h>

namespace powerAuth::jni {

using namespace cc7::jni;

/// The `NativeHelper` helps with processing JNI calls specific for PowerAuth SDK.
class NativeHelper
{
public:
    /// Register a ClassSpec initialization into `JNIGlobal` initialization sequence.
    /// The function should be called only for once during the application's lifetime.
    static void registerGlobalJniInitializers();

    /// Get reference to NativeHelper's singleton instance.
    static const NativeHelper& helper();

    /// Get reference to ClassSpec structure containing specifications for PowerAuth specific Java classes.
    const ClassSpecs& classSpecs() const noexcept { return _specs; }

    /// Handle exception thrown from C++ code.
    ///
    /// Example:
    ///
    /// ```cpp
    /// auto jni = JNIGlobal::local(env);
    /// try {
    ///     // any C++ code
    /// } catch (...) {
    ///     NativeHelper::handleException(jni);
    /// }
    /// ```
    static void handleException(cc7::jni::JNI& jni, std::exception_ptr exception = std::current_exception());

    /// Handle exception thrown from C++ code. Unlike `handleException()` this method processes only exceptions from `cc7::jni`
    /// namespace. All such exceptions are marshalled to RuntimeException types, so it's useful for functions that
    /// doesn't throw `CoreException`.
    static void handleJniExceptionsOnly(cc7::jni::JNI& jni, std::exception_ptr exception = std::current_exception());

private:

    bool _init_registered = false;
    bool _initialized = false;
    ClassSpecs _specs = {};
};

/// Macro creates a `JNI jni` variable on the stack and begins try - catch block. You should complete the block
/// with using `NH_CATCH()` or `NH_NO_THROW()` macro.
///
/// Example:
/// ```cpp
/// CC7_JNI_STATIC_METHOD_PARAMS(void, compareObjects, jobject obj1, jobject obj2)
/// {
///     NH_TRY {
///         jni.requireParameter(obj1, "obj1");
///         jni.requireParameter(obj1, "obj2");
///         return jni.isEqual(obj1, obj2);
///     } NH_CATCH(false)
/// }
/// ```
#define NH_TRY                                               \
    auto jni = cc7::jni::JNIGlobal::local(env);              \
    try

/// Macro ends try - catch block started in `NH_TRY` and translates any known C++ exception into Java exception.
/// @param return_value Defines a value returned in case the exception occurred. In case this is JNI function
///        returning `void`, then you use nothing form parameter.
#define NH_CATCH(return_value)                                      \
    catch (...) {                                                   \
        powerAuth::jni::NativeHelper::handleException(jni);         \
        return return_value;                                        \
    }

/// Macro ends try - catch block started in `NH_TRY` and translates `cc7::jni` C++ exceptions into Java RuntimeException
/// types. If other than `cc7::jni` exception is raised, then `IllegalStateException` is reported back to java.
///
/// This is useful for methods that suppose not to throw `CoreException`.
///
/// @param return_value Defines a value returned in case the exception occurred. In case this is JNI function
///        returning `void`, then you use nothing form parameter.
#define NH_CATCH_RT_ONLY(return_value)                              \
    catch (...) {                                                   \
        powerAuth::jni::NativeHelper::handleJniExceptionsOnly(jni); \
        return return_value;                                        \
    }

/// Macro ends try - catch block started by `NH_TRY` and swallows all C++ exceptions.
/// @param return_value Defines a value returned in case the exception occurred. In case this is JNI function
///        returning `void`, then you use nothing form parameter.
#define NH_NO_THROW(return_value)                                   \
    catch (...) {                                                   \
        jni.noThrow();                                              \
        return return_value;                                        \
    }

/// Get reference to class specifications provided by NativeHelper.
#define NH_SPECS() powerAuth::jni::NativeHelper::helper().classSpecs()

/// Get reference to common class specifications provided by JNI instance.
#define NH_COMMON_SPECS() jni.commonSpecs()

// Support functions

/// Closure for constructing Java model objects from C++ response objects.
typedef std::function<
        jobject(cc7::jni::JNI& jni,
                const ClassSpecs& specs,
                const powerAuth::ResponseObjectPtr& response
        )> ResponseObjectBuilder;

/// Structure contains information required for response object build.
struct JavaResponseBuilder
{
    ResponseObjectBuilder build;
};

/// Build CoreRequest Java object from given C++ Request instance.
/// @param jni JNI reference.
/// @param request Request object.
/// @return CoreRequest Java instance.
jobject BuildCoreRequest(cc7::jni::JNI &jni, const RequestPtr& request);

/// Build CoreRequest Java object from given C++ Request instance and set closure that translates received response into Java response object.
/// @param jni JNI reference.
/// @param request Request object.
/// @param builder Closure that translates received C++ response object into Java response object.
/// @return CoreRequest Java instance with additional builder closure.
jobject BuildCoreRequest(cc7::jni::JNI &jni, const RequestPtr& request, const ResponseObjectBuilder& builder);

/// Build CoreTask Java object from given C++ Task instance.
/// @param jni JNI reference.
/// @param task Task object.
/// @return CoreTask Java instance.
jobject BuildCoreTask(cc7::jni::JNI& jni, const TaskPtr& task);

/// Build CoreTask Java object from given C++ Task instance and set closure that translates received response into Java response object.
/// @param jni JNI reference.
/// @param task Task object.
/// @param builder Closure that translates received C++ response object into Java response object.
/// @return CoreTask Java instance with additional builder closure.
jobject BuildCoreTask(cc7::jni::JNI &jni, const TaskPtr& task, const ResponseObjectBuilder& builder);

} // namespace powerAuth::jni
