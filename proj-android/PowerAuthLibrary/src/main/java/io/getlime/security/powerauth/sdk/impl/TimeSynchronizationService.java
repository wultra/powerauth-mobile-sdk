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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.core.ICoreTimeService;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;
import io.getlime.security.powerauth.sdk.IPowerAuthTimeSynchronizationService;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The `TimeService` class provides time synchronization with the server.
 * However, the class itself does not handle communication with the PowerAuth server
 * to achieve this synchronization. Instead, you must use your own code in conjunction
 * with the `startTimeSynchronizationTask` and `completeTimeSynchronizationTask` methods.
 */
public class TimeSynchronizationService implements ICoreTimeService, IPowerAuthTimeSynchronizationService {

    private final ITimeProvider timeProvider;
    private final IServerStatusProvider serverStatusProvider;
    private final ICallbackDispatcher callbackDispatcher;

    private boolean isTimeSynchronized = false;
    private long localTimeAdjustment = 0L;
    private long localTimeAdjustmentPrecision = 0L;

    /**
     * Minimum time difference against the server accepted during the synchronization. If the difference
     * is less, then we consider the local time as synchronized.
     */
    final long MIN_ACCEPTED_TIME_DIFFERENCE = 2_000;
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


    @FunctionalInterface
    public interface ITimeProvider {
        /**
         * Implementation should provide a milliseconds precision timestamp since 1.1.1970.
         * @return Elapsed time in milliseconds since 1.1.1970
         */
        long getCurrentTime();
    }

    /**
     * Construct the time service with the internal TimeProvider instance. The constructor and the interface
     * are package private but suppose to be used only for the testing purposes.
     * @param timeProvider Instance implementing ITimeProvider interface.
     * @param serverStatusProvider Instance implementing IServerStatusProvider interface.
     * @param callbackDispatcher Instance implementing ICallbackDispatcher
     */
    public TimeSynchronizationService(
            @NonNull ITimeProvider timeProvider,
            @NonNull IServerStatusProvider serverStatusProvider,
            @NonNull ICallbackDispatcher callbackDispatcher) {
        this.timeProvider = timeProvider;
        this.serverStatusProvider = serverStatusProvider;
        this.callbackDispatcher = callbackDispatcher;
    }


    @Override
    public long getLocalTimeAdjustment() {
        synchronized (this) {
            return localTimeAdjustment;
        }
    }

    @Override
    public long getLocalTimeAdjustmentPrecision() {
        synchronized (this) {
            return localTimeAdjustmentPrecision;
        }
    }

    // ITimeService interface implementation

    @Override
    public boolean isTimeSynchronized() {
        synchronized (this) {
            return isTimeSynchronized;
        }
    }
    @Override
    public @NonNull Object startTimeSynchronizationTask() {
        return timeProvider.getCurrentTime();
    }

    @Override
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
            long adjustedTimePrecision = elapsedTime >> 1;                // elapsedTime / 2
            long adjustedServerTime = serverTime + adjustedTimePrecision; // serverTime + elapsedTime / 2
            long timeDifference = adjustedServerTime - now;
            boolean adjustmentDeltaOK = Math.abs(localTimeAdjustment - timeDifference) < MIN_TIME_DIFFERENCE_DELTA;
            if (Math.abs(timeDifference) < MIN_ACCEPTED_TIME_DIFFERENCE && adjustmentDeltaOK) {
                // Time difference is too low and delta against last adjustment is also within the range.
                // We can ignore it and mark time as synchronized.
                PowerAuthLog.d("PowerAuthTimeService: Time is synchronized with precision " + adjustedTimePrecision);
                isTimeSynchronized = true;
                localTimeAdjustmentPrecision = adjustedTimePrecision;
                return true;
            }
            if (isTimeSynchronized && adjustmentDeltaOK) {
                // The time adjustment is too low against the last calculated adjustment. This test prevents
                // the adjusted time fluctuation after each synchronization.
                return true;
            }
            // Keep local time adjustment and mark time as synchronized.
            PowerAuthLog.d("PowerAuthTimeService: Time is synchronized with precision " + adjustedTimePrecision + ", diff" + timeDifference);
            localTimeAdjustment = timeDifference;
            localTimeAdjustmentPrecision = adjustedTimePrecision;
            isTimeSynchronized = true;
            return true;
        }
    }

    @Override
    public long getCurrentTime() {
        synchronized (this) {
            return timeProvider.getCurrentTime() + localTimeAdjustment;
        }
    }

    @Nullable
    @Override
    public ICancelable synchronizeTime(@NonNull ITimeSynchronizationListener listener) {
        if (isTimeSynchronized()) {
            callbackDispatcher.dispatchCallback(listener::onTimeSynchronizationSucceeded);
            return null;
        }
        final Object timeSynchronizationTask = startTimeSynchronizationTask();
        return serverStatusProvider.getServerStatus(new IServerStatusListener() {
            @Override
            public void onServerStatusSucceeded(@NonNull ServerStatus serverStatus) {
                if (!completeTimeSynchronizationTask(timeSynchronizationTask, serverStatus.getServerTime())) {
                    listener.onTimeSynchronizationFailed(new PowerAuthErrorException(PowerAuthErrorCodes.TIME_SYNCHRONIZATION, "Failed to synchronize time with the server"));
                    return;
                }
                listener.onTimeSynchronizationSucceeded();
            }

            @Override
            public void onServerStatusFailed(@NonNull Throwable t) {
                listener.onTimeSynchronizationFailed(t);
            }
        });
    }

    @Override
    public void resetTimeSynchronization() {
        synchronized (this) {
            isTimeSynchronized = false;
            localTimeAdjustment = 0L;
            localTimeAdjustmentPrecision = 0L;
        }
    }
}
