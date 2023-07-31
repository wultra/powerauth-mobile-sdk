/*
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The `TimeService` class provides time synchronization with the server.
 * However, the class itself does not handle communication with the PowerAuth server
 * to achieve this synchronization. Instead, you must use your own code in conjunction
 * with the `startTimeSynchronizationTask` and `completeTimeSynchronizationTask` methods.
 */
public class TimeService {

    private boolean isTimeSynchronized = false;
    private long localTimeAdjustment = 0L;
    private final TimeProvider timeProvider;

    /**
     * Minimum time difference against the server accepted during the synchronization. If the difference
     * is less, then we consider the local time as synchronized.
     */
    final long MIN_ACCEPTED_TIME_DIFFERENCE = 10_000;
    /**
     * Minimum difference against the last time delta. This prevents the time fluctuation the time is synchronized.
     * For example, if the server is 100 seconds ahead, then we'll get differences like 100.1, 101, 99.8 and that might
     * cause a time fluctuation after each synchronization attempt. That means that the synchronized time may jump a
     * little bit back or forward after each synchronization attempt.
     */
    final long MIN_TIME_DIFFERENCE_DELTA = 10_000;
    /**
     * Maximum time for the request synchronization to complete.
     * In this setup we're adding maximum 8 seconds to the time returned from the server, so it's below our threshold
     * defined in `MIN_ACCEPTED_TIME_DIFFERENCE`. This guarantees that requests that take too long time will not affect
     * the time synchronization.
     */
    final long MAX_ACCEPTED_ELAPSED_TIME = 16_000;

    /**
     * @return Information whether the service has its time synchronized with the server.
     */
    public boolean isTimeSynchronized() {
        synchronized (this) {
            return isTimeSynchronized;
        }
    }

    /**
     * @return Contains calculated local time difference against the server. The value  is informational and is
     * provided only for the testing or the debugging purposes.
     */
    public long getLocalTimeAdjustment() {
        synchronized (this) {
            return localTimeAdjustment;
        }
    }

    /**
     * Start time synchronization task and return object representing such task. The same object must be later
     * provided to {@link #completeTimeSynchronizationTask(Object, long)} method.
     * @return Object representing a time synchronization task.
     */
    @NonNull
    public Object startTimeSynchronizationTask() {
        return timeProvider.getCurrentTime();
    }

    /**
     * Complete the time synchronization task with time received from the server.
     * @param task Task object created in {@link #startTimeSynchronizationTask()} method.
     * @param serverTime Timestamp received from the server with the milliseconds' precision.
     * @return true if the server time has been processed and time is synchronized now.
     */
    public boolean completeTimeSynchronizationTask(@NonNull Object task, long serverTime) {
        if (!(task instanceof Long)) {
            PowerAuthLog.e("TimeService: Wrong task object used for the commit.");
            return false;
        }
        synchronized (this) {
            final long now = timeProvider.getCurrentTime();
            final long start = (long)task;
            final long elapsedTime = now - start;
            if (elapsedTime < 0) {
                PowerAuthLog.e("TimeService: Wrong task object used for the commit.");
                return false;
            }
            if (elapsedTime > MAX_ACCEPTED_ELAPSED_TIME) {
                PowerAuthLog.e("TimeService: Synchronization request took too long to complete.");
                // Return the current synchronization status. We can be OK if the time was synchronized before.
                return isTimeSynchronized;
            }
            long adjustedServerTime = serverTime + (elapsedTime >> 1); // serverTime + elapsedTime / 2
            long timeDifference = adjustedServerTime - now;
            boolean adjustmentDeltaOK = Math.abs(localTimeAdjustment - timeDifference) < MIN_TIME_DIFFERENCE_DELTA;
            if (Math.abs(timeDifference) < MIN_ACCEPTED_TIME_DIFFERENCE && adjustmentDeltaOK) {
                // Time difference is too low and delta against last adjustment is also within the range.
                // We can ignore it and mark time as synchronized.
                isTimeSynchronized = true;
                return true;
            }
            if (isTimeSynchronized && adjustmentDeltaOK) {
                // The time adjustment is too low against the last calculated adjustment. This test prevents
                // the adjusted time fluctuation after each synchronization.
                return true;
            }
            // Keep local time adjustment and mark time as synchronized.
            localTimeAdjustment = timeDifference;
            isTimeSynchronized = true;
            return true;
        }
    }

    /**
     * @return The current local time synchronized with the server. The returned value is in the milliseconds since the
     * reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
     * the current local time (e.g. `System.currentTimeMillis()`.) You can test `isTimeSynchronized` property if
     * this is not sufficient for your purposes.
     */
    public long getCurrentTime() {
        synchronized (this) {
            return timeProvider.getCurrentTime() + localTimeAdjustment;
        }
    }

    /**
     * Reset the time synchronization. The time must be synchronized again after this call.
     */
    public void resetTimeSynchronization() {
        synchronized (this) {
            isTimeSynchronized = false;
            localTimeAdjustment = 0;
        }
    }

    interface TimeProvider {
        /**
         * Implementation should provide a milliseconds precision timestamp since 1.1.1970.
         * @return Elapsed time in milliseconds since 1.1.1970
         */
        long getCurrentTime();
    }

    /**
     * Construct the time service with the internal TimeProvider instance. The constructor and the interface
     * are package private but suppose to be used only for the testing purposes.
     * @param timeProvider Instance of TimeProvider interface.
     */
    TimeService(@NonNull TimeProvider timeProvider) {
        this.timeProvider = timeProvider;
    }

    private static class Singleton {
        private static final TimeService INSTANCE = new TimeService(System::currentTimeMillis);
    }

    /**
     * @return Singleton instance of TimeService class.
     */
    @NonNull
    public static TimeService getInstance() {
        return Singleton.INSTANCE;
    }

}
