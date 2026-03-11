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
#include <PowerAuth/TimeService.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreTimeService
#define CC7_JNI_CPP_CLASS           TimeService
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;
using namespace cc7::json;
using namespace cc7::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreTimeService, thiz)

CC7_JNI_METHOD(jboolean, isTimeSynchronized)
{
    NH_TRY
    {
        return THIS_OBJ()->isTimeSynchronized();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jlong, getCurrentTime)
{
    NH_TRY
    {
        return THIS_OBJ()->currentTimeMillis();
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jlong, getLocalTimeAdjustment)
{
    NH_TRY
    {
        return TimeIntervalToTimestamp(THIS_OBJ()->localTimeAdjustment());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jlong, getLocalTimeAdjustmentPrecision)
{
    NH_TRY
    {
        return TimeIntervalToTimestamp(THIS_OBJ()->localTimeAdjustmentPrecision());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jobject, createTimeSynchronizationRequest)
{
    NH_TRY
    {
        auto request = THIS_OBJ()->createTimeSynchronizationRequest();
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto status = std::dynamic_pointer_cast<ServerStatus>(response);
            if (!status) {
                throw Exception(EC_InternalError, "No ServerStatus object created");
            }
            return jni.createObject(specs.respServerStatus.methods.initTimeNameVersion,
                                    status->serverTime(),
                                    jni.toJava(status->applicationName()),
                                    jni.toJava(status->applicationVersion()));
        });
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jboolean, hasPendingTimeSynchronizationRequest)
{
    NH_TRY
    {
        return THIS_OBJ()->hasPendingSynchronizationRequest();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(void, resetTimeSynchronization)
{
    NH_TRY
    {
        THIS_OBJ()->resetTimeSynchronization();
    }
    NH_CATCH_RT_ONLY()
}

CC7_JNI_MODULE_CLASS_END()
