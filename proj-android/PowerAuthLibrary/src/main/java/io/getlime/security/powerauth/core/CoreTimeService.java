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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.response.CoreServerStatus;

/**
 * The {@code CoreTimeService} class provides functionality for getting
 * time synchronized with the server and allows synchronize time with the server.
 */
public class CoreTimeService extends NativeObject {
    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     */
    protected CoreTimeService(long nativeObjectHandle) {
        super(nativeObjectHandle);
    }

    /**
     * @return Information whether the service has its time synchronized with the server.
     */
    public native boolean isTimeSynchronized();

    /**
     * Get the current local time synchronized with the server. The returned value is in the milliseconds
     * since the reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized,
     * then returns the current local time. You can call {@link #isTimeSynchronized()}  if this is
     * not sufficient for your purposes.
     *
     * @return Get the current local time synchronized with the server.
     */
    public native long getCurrentTime();

    /**
     * Get calculated local time difference against the server. The value  is informational and is
     * provided only for the testing or the debugging purposes.
     * <p>
     * The returned value is in milliseconds precision (e.g. 1000 represents one second)
     *
     * @return local time difference against the server.
     */
    public native long getLocalTimeAdjustment();

    /**
     * Get value representing a maximum absolute deviation of synchronized time against the actual
     * time on the server. Depending on this value you can determine whether this deviation is
     * within your expected margins. If the current synchronized time is out of your expectations,
     * then try to synchronize the time again.
     * <p>
     * The returned value is in milliseconds precision (e.g. 1000 represents one second)
     *
     * @return Value representing a maximum absolute deviation of synchronized time against the
     *         actual time on the server.
     */
    public native long getLocalTimeAdjustmentPrecision();

    /**
     * Creates HTTP request for time synchronization.
     * @return {@link CoreRequest}
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<CoreServerStatus> createTimeSynchronizationRequest() throws CoreException;

    /**
     * Get information whether there's already pending request for time synchronization.
     * @return {@code true} if there's pending request for time synchronization.
     */
    public native boolean hasPendingTimeSynchronizationRequest();

    /**
     * Reset time synchronization.
     */
    public native void resetTimeSynchronization();
}
