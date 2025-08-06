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

#include <PowerAuth/TimeService.h>
#include <cc7/Time.h>

#include "request/RequestBuilder.h"
#include "Context.h"

namespace powerAuth {

// MARK: - Default time provider

class DefaultTimeProvider : public ITimeProvider
{
public:
    TimeInterval getCurrentTime() const override
    {
        return cc7::GetCurrentTime();
    }
    
    Timestamp getCurrentTimeMillis() const override
    {
        return cc7::GetCurrentTimeMillis();
    }
};


// MARK: - TimeService

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

const double TimeService::MIN_ACCEPTED_TIME_DIFFERENCE = 2.0;
const double TimeService::MIN_TIME_DIFFERENCE_DELTA = 10.0;
const double TimeService::MAX_ACCEPTED_ELAPSED_TIME = 16.0;

TimeService::TimeService(const ContextPtr& context) :
    _weak_context(context),
    _time_provider(std::make_shared<DefaultTimeProvider>()),
    _lock(context->getSharedMutexPtr()),
    _is_synchronized(false),
    _local_time_adjustment(0.0),
    _local_time_adjustment_precision(0.0),
    _current_sync_task(-1)
{
}

TimeService::TimeService(ITimeProviderPtr time_provider, SharedMutexPtr shared_lock) :
    _time_provider(time_provider != nullptr ? time_provider : std::make_shared<DefaultTimeProvider>()),
    _lock(shared_lock != nullptr ? shared_lock : std::make_shared<SharedMutex>()),
    _is_synchronized(false),
    _local_time_adjustment(0.0),
    _local_time_adjustment_precision(0.0),
    _current_sync_task(-1)
{
}

Timestamp TimeService::currentTimeMillis() const
{
    return (Timestamp)(1000.0 * currentTime());
}

TimeInterval TimeService::currentTime() const
{
    LOCK_GUARD();
    return _time_provider->getCurrentTime() + _local_time_adjustment;
}

bool TimeService::isTimeSynchronized() const
{
    LOCK_GUARD();
    return _is_synchronized;
}

TimeInterval TimeService::localTimeAdjustment() const
{
    LOCK_GUARD();
    return _local_time_adjustment;
}

TimeInterval TimeService::localTimeAdjustmentPrecision() const
{
    LOCK_GUARD();
    return _local_time_adjustment_precision;
}

TimeService::TaskId TimeService::startTimeSynchronizationTask()
{
    auto task = _time_provider->getCurrentTime();
    //CC7_LOG("TimeService: Sync task %f started", task);
    return task;
}

bool TimeService::completeTimeSynchronizationTask(TaskId task_id, TimeInterval server_time)
{
    LOCK_GUARD();
    auto now = _time_provider->getCurrentTime();
    auto start = task_id;
    auto elapsedTime = now - start;
    //CC7_LOG("TimeService: Sync task %f ended at %f (elapsed %f)", task_id, now, elapsedTime);
    if (elapsedTime < 0.0) {
        CC7_LOG("TimeService: Wrong task-id value used for the synchronization");
        return _is_synchronized;
    }
    if (elapsedTime > MAX_ACCEPTED_ELAPSED_TIME) {
        CC7_LOG("TimeService: Synchronization request took too long to complete");
        return _is_synchronized;
    }
    auto timeDifferencePrecision = 0.5 * elapsedTime;
    auto adjustedServerTime = server_time + timeDifferencePrecision; // serverTime + elapsedTime/2
    auto timeDifference = adjustedServerTime - now;
    auto adjustmentDeltaOK = fabs(_local_time_adjustment - timeDifference) < MIN_TIME_DIFFERENCE_DELTA;
    if (fabs(timeDifference) < MIN_ACCEPTED_TIME_DIFFERENCE && adjustmentDeltaOK) {
        // Time difference is too low and delta against last adjustment is also within the range.
        // We can ignore it and mark time as synchronized.
        if (!_is_synchronized) {
            // Print this information only when not synchronized.
            CC7_LOG("TimeService: Time is synchronized with precision %0.3lf", timeDifferencePrecision);
        }
        _is_synchronized = true;
        _local_time_adjustment_precision = timeDifferencePrecision;
        return true;
    }
    if (_is_synchronized && adjustmentDeltaOK) {
        // The time adjustment is too low against the last calculated adjustment. This test prevents
        // the adjusted time fluctuation after each synchronization.
        return true;
    }
    // Keep local time adjustment and mark time as synchronized.
    _is_synchronized = true;
    _local_time_adjustment = timeDifference;
    _local_time_adjustment_precision = timeDifferencePrecision;
    CC7_LOG("TimeService: Time is synchronized with precision %0.3lf, diff %0.3lf", timeDifferencePrecision, timeDifference);
    return true;
}

void TimeService::resetTimeSynchronization()
{
    LOCK_GUARD();
    _is_synchronized = false;
    _local_time_adjustment = 0.0;
    _local_time_adjustment_precision = 0.0;
    _current_sync_task = -1;
    
    CC7_LOG("TimeService: Time is no longer synchronized");
}


RequestPtr TimeService::createTimeSynchronizationRequest()
{
    LOCK_GUARD();
    if (_current_sync_task > 0) {
        throw Exception(EC_NotAllowed, "Time synchronization is already in progress");
    }
    if (auto context = _weak_context.lock()) {
        CC7_LOG("TimeService: Time synchronization request created");
        _current_sync_task = startTimeSynchronizationTask();
        auto self = shared_from_this();
        return RequestBuilder(*context, v4::Endpoint_SystemStatus)
            .withResponseCallback([self](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
                return self->processTimeSynchronization(response);
            })
            .withCancelCallback([self]() {
                self->cancelTimeSynchronization();
            })
            .build();
    }
    // No context means Session is already dead.
    throw Exception(EC_NotAllowed, "Session object is destroyed");
}

ResponseObjectPtr TimeService::processTimeSynchronization(const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    CC7_LOG("TimeService: Time synchronization response received");
    if (_current_sync_task < 0) {
        throw Exception(EC_NotAllowed, "No time synchronization in progress");
    }
    
    auto task = _current_sync_task;
    _current_sync_task = -1;
    auto time = response["serverTime"].asInteger();

    completeTimeSynchronizationTask(task, TimestampToTimeInterval(time));
    
    return nullptr;
}

void TimeService::cancelTimeSynchronization()
{
    LOCK_GUARD();
    if (_current_sync_task < 0) {
        CC7_LOG("TimeService: Time synchronization request canceled");
        _current_sync_task = -1;
    }
}

bool TimeService::hasPendingSynchronizationRequest() const noexcept
{
    LOCK_GUARD();
    return _current_sync_task > 0.0;
}

} // namespace powerAuth

