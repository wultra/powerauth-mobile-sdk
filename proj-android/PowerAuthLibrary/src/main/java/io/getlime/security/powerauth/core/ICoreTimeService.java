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

/**
 * The {@code ITimeService} inteface provides functionality for getting time synchronized with the server
 * and allows implement time synchronization with the server.
 */
public interface ICoreTimeService {
    /**
     * @return Information whether the service has its time synchronized with the server.
     */
    boolean isTimeSynchronized();

    /**
     * @return The current local time synchronized with the server. The returned value is in the milliseconds since the
     * reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
     * the current local time (e.g. `System.currentTimeMillis()`.) If this is not sufficient for your purposes then
     * you can call {@link #isTimeSynchronized()} before you get the time.
     */
    long getCurrentTime();

    /**
     * Start time synchronization task and return object representing such task. The same object must be later
     * provided to {@link #completeTimeSynchronizationTask(Object, long)} method.
     * @return Object representing a time synchronization task.
     */
    @NonNull
    Object startTimeSynchronizationTask();

    /**
     * Complete the time synchronization task with time received from the server.
     * @param task Task object created in {@link #startTimeSynchronizationTask()} method.
     * @param serverTime Timestamp received from the server with the milliseconds' precision.
     * @return true if the server time has been processed and time is synchronized now.
     */
    boolean completeTimeSynchronizationTask(@NonNull Object task, long serverTime);
}
