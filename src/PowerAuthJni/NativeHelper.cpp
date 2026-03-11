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

namespace powerAuth::jni {

static NativeHelper& GetInstance()
{
    static NativeHelper instance {};
    return instance;
}

static std::mutex& GetInstanceMutex()
{
    static std::mutex mutex;
    return mutex;
}

void NativeHelper::registerGlobalJniInitializers()
{
    std::lock_guard<std::mutex> lock(GetInstanceMutex());
    auto& instance = GetInstance();
    if (instance._init_registered) {
        throw JniFatalException("powerAuth::jni::NativeHelper already registered its initializer");
    }
    JNIGlobal::addGlobalInitializer([](JNI& jni){
        std::lock_guard<std::mutex> lock(GetInstanceMutex());
        auto& instance = GetInstance();
        instance._specs = ClassSpecs::buildSpecs(jni);
        instance._initialized = true;
    });
    instance._init_registered = true;
}

const NativeHelper& NativeHelper::helper()
{
    std::lock_guard<std::mutex> lock(GetInstanceMutex());
    auto& instance = GetInstance();
    if (!instance._initialized) {
        throw cc7::jni::JniFatalException("powerAuth::jni::NativeHelper is not initialized yet");
    }
    return instance;
}

void NativeHelper::handleException(cc7::jni::JNI &jni, std::exception_ptr exception)
{
    if (jni.processException(exception, true)) {
        // Already handled
        return;
    }

    // This is similar to BuildNSErrorFromException() on iOS platform.

    std::string message;
    std::vector<std::string> additional_info;

    auto error_code =  powerAuth::EC_Other;
    auto ptr = Exception::wrapException(exception);
    while (ptr != nullptr) {
        std::string cpp_message;
        auto ec = powerAuth::EC_Other;
        try {
            std::rethrow_exception(ptr);
        } catch (powerAuth::Exception & e) {
            cpp_message = e.exceptionClass() + ": " + e.message();
            ptr = e.cause();
            ec = e.error();
        } catch (cc7::BaseException & e) {
            cpp_message = e.exceptionClass() + ": " + e.message();
            ptr = e.cause();
        } catch (std::exception & e) {
            cpp_message = e.what();
            ptr = nullptr;
        } catch (...) {
            cpp_message = "Unknown exception type";
            ptr = nullptr;
        }
        if (cpp_message.empty()) {
            cpp_message = Exception::defaultMessage(error_code);
        }
        if (message.empty()) {
            // First message not set,
            message = cpp_message;
            error_code = ec;
        }
    }
    // Convert additional_info vector into String[] array.
    auto java_info = jni.createObjectArray(jni.commonSpecs().classString, additional_info.size(), true);
    for (auto i = 0; i < additional_info.size(); i++) {
        java_info.setObject(i, jni.toJava(additional_info[i]));
    }
    const auto& specs = helper().classSpecs();
    // Throw custom exception to Java:
    // - CoreException(@CoreErrorCode int errorCode, @Nullable String message, @Nullable String[] additionalFailureInfo)
    jni.throwToJava(specs.coreException.methods.initCodeMessageInfo,
                    jni.toJava<>(specs.coreErrorCode, error_code),
                    jni.toJava(message),
                    java_info.array());
}

void NativeHelper::handleJniExceptionsOnly(cc7::jni::JNI& jni, std::exception_ptr exception)
{
    jni.processException(exception, false);
}

} // namespace powerAuth::jni
