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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;

public interface IPowerAuthTimeSynchronizationService {
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
     * @return Contains calculated local time difference against the server. The value  is informational and is
     * provided only for the testing or the debugging purposes.
     */
    long getLocalTimeAdjustment();

    /**
     * Get value representing a maximum absolute deviation of synchronized time against the actual time on the server.
     * Depending on this value you can determine whether this deviation is within your expected margins. If the current
     * synchronized time is out of your expectations, then try to synchronize the time again.
     * @return Maximum absolute deviation of synchronized time against the actual time on the server in milliseconds.
     */
    long getLocalTimeAdjustmentPrecision();

    /**
     * Synchronize the local with the time on the server.
     * @param listener Listener to call once the operation is completed.
     * @return Cancelable object associated with underlying HTTP request.
     */
    @Nullable ICancelable synchronizeTime(@NonNull ITimeSynchronizationListener listener);

    /**
     * Reset the time synchronization. The time must be synchronized again after this call.
     */
    void resetTimeSynchronization();
}
