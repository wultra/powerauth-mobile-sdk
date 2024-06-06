/*
 * Copyright 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.system;

import androidx.annotation.NonNull;

/**
 * Interface that represents a listener that can tap into the library logs and use them for example
 * to report to a online system or to a logfile for user to send with some report. Note that by default
 * all logs are logged into the Logcat.
 *
 * @author Jan Kobersky
 */
public interface PowerAuthLogListener {

    /**
     * Debug message reported by the library. Debug messages are only reported when
     * {@link PowerAuthLog} setEnabled is set to true.
     *
     * @param message Debug message.
     */
    void powerAuthDebugLog(@NonNull String message);

    /**
     * Warning reported by the library.
     *
     * @param message Warning message.
     */
    void powerAuthWarningLog(@NonNull String message);

    /**
     * Error reported by the library.
     *
     * @param message Error message.
     */
    void powerAuthErrorLog(@NonNull String message);
}
