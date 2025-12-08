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
    static NativeHelper instance;
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
    if (instance._initialized) {
        // Initialization handler is already registered
        return;
    }
    JNIGlobal::addGlobalInitializer([](JNI& jni){
        std::lock_guard<std::mutex> lock(GetInstanceMutex());
        auto& instance = GetInstance();
        instance._specs = ClassSpecs::buildSpecs(jni);
        instance._initialized = true;
    });
}

const NativeHelper& NativeHelper::helper()
{
    std::lock_guard<std::mutex> lock(GetInstanceMutex());
    auto& instance = GetInstance();
    if (instance._initialized) {
        throw cc7::jni::JniFatalException("powerAuth::jni::NativeHelper is not initialized yet");
    }
    return instance;
}

void NativeHelper::handleException(cc7::jni::JNI &jni, std::exception_ptr exception)
{
    if (jni.processException(exception)) {
        return;
    }
    // TODO: process other exceptions
}

} // namespace powerAuth::jni
