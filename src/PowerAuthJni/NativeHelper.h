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
#include <PowerAuth/Password.h>
#include <PowerAuth/Exception.h>

namespace powerAuth::jni {

using namespace cc7::jni;


class NativeHelper
{
public:

    static void registerGlobalJniInitializers();

    static const NativeHelper& helper();

    const ClassSpecs& classSpecs() const noexcept { return _specs; }

    static void handleException(cc7::jni::JNI& jni, std::exception_ptr exception = std::current_exception());

private:

    bool _initialized = false;
    ClassSpecs _specs;
};

#define NH_TRY                                               \
    auto jni = cc7::jni::JNIGlobal::local(env);              \
    try

#define NH_CATCH(return_value)                               \
    catch (...) {                                            \
        powerAuth::jni::NativeHelper::handleException(jni);  \
        return return_value;                                 \
    }

#define NH_NO_THROW(return_value)                            \
    catch (...) {                                            \
        jni.noThrow();                                       \
        return return_value;                                 \
    }

#define NH_SPECS() powerAuth::jni::NativeHelper::helper().classSpecs()

} // namespace powerAuth::jni
