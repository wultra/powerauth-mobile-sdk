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

#include <PowerAuth/Types.h>
#include <PowerAuth/Exception.h>
#include <cc7/BaseObject.h>
#include <cc7/Time.h>

namespace powerAuth {

/// The `TimeProvider` is abstract class that provide time.
class ITimeProvider : public cc7::BaseObject
{
public:
    /// Function returns current time in seconds, elapsed since reference date 1.1.1970. The time
    /// is represented in floating point value.
    virtual TimeInterval getCurrentTime() const = 0;
    
    /// Function returns current time in milliseconds, elapsed since reference date 1.1.1970. The time
    /// is represented in 64 bit integer value.
    virtual Timestamp getCurrentTimeMillis() const = 0;
};

CC7_SHARED_PTR(ITimeProvider)

/// The `TimeService` class provides time synchronized with the server.
class TimeService
{
public:
    /// The `TaskId` is value type representing a time synchronization task.
    typedef TimeInterval TaskId;

    /// Return the current local time synchronized with the server. The returned value is in the milliseconds since the
    /// reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
    /// the current local time (e.g. `gettimeofday()`.) You can test `isTimeSynchronized` property if
    /// this is not sufficient for your purposes.
    Timestamp currentTimeMillis() const;
    
    /// Return the current local time synchronized with the server. The returned value is in the seconds since the
    /// reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
    /// the current local time (e.g. `gettimeofday()`.) You can test `isTimeSynchronized` property if
    /// this is not sufficient for your purposes.
    TimeInterval currentTime() const;
    
    /// Return information whether the service has its time synchronized with the server.
    bool isTimeSynchronized() const;
    
    /// Return calculated local time difference against the server. The value  is informational and is provided only
    /// for the testing or the debugging purposes.
    TimeInterval localTimeAdjustment() const;
    
    /// Return value representing a maximum absolute deviation of synchronized time against the actual time on the server.
    /// Depending on this value you can determine whether this deviation is within your expected margins. If the current
    /// synchronized time is out of your expectations, then try to synchronize the time again.
    TimeInterval localTimeAdjustmentPrecision() const;
    
    /// Start the time synchronization task and return value representing such task. The same object must be later
    /// provided to `completeTimeSynchronizationTask()` method.
    TaskId startTimeSynchronizationTask();

    /// Complete the time synchronization task with time received from the server.
    /// - Parameters:
    ///   - task: Task object created in `startTimeSynchronizationTask` function.
    ///   - server_time: TimeInterval with seconds precision, received from the server.
    /// - Returns: YES if the server time has been processed and time is now synchronized.
    bool completeTimeSynchronizationTask(TaskId task_id, TimeInterval server_time);
    
    /// Reset the time synchronization. The time must be synchronized again after this call.
    void resetTimeSynchronization();

    
    // Construction & Constants
    
    /// Construct service with optional TimeProvider and SharedMutex objects.
    /// - Parameters:
    ///   - time_provider: Pointer to `TimeProvider` implementation. If `nullptr` is used, then the default implementation will be set.
    ///   - shared_lock: Pointer to `SharedMutex` object. If `nullptr` is used, then the service will create its own private mutex to achieve the thread safety.
    TimeService(ITimeProviderPtr time_provider = nullptr, SharedMutexPtr shared_lock = nullptr);
    
    /// Minimum time difference against the server accepted during the synchronization. If the difference
    /// is less, then we consider the local time as synchronized.
    static const TimeInterval MIN_ACCEPTED_TIME_DIFFERENCE;
    /// Minimum difference against the last time delta. This prevents the time fluctuation the time is synchronized.
    /// For example, if the server is 100 seconds ahead, then we'll get differences like 100.1, 101, 99.8 and that might cause
    /// a time fluctuation after each synchronization attempt. That means that the synchronized time may jump a little bit
    /// back or forward after each synchronization attempt.
    static const TimeInterval MIN_TIME_DIFFERENCE_DELTA;
    
    /// Maximum time for the request synchronization to complete.
    /// In this setup we're adding maximum 8 seconds to the time returned from the server, so it's below our threshold
    /// defined in `MIN_ACCEPTED_TIME_DIFFERENCE`. This guarantees that requests that take too long time will not affect
    /// the time synchronization.
    static const TimeInterval MAX_ACCEPTED_ELAPSED_TIME;
    
private:
    
    const SharedMutexPtr _lock;
    const ITimeProviderPtr _time_provider;
    
    bool _is_synchronized;
    TimeInterval _local_time_adjustment;
    TimeInterval _local_time_adjustment_precision;
};

CC7_SHARED_PTR(TimeService)

} // namespace powerAuth
