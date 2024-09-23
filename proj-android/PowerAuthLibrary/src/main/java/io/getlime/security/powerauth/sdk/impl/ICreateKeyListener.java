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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.MainThread;
import androidx.annotation.NonNull;

/**
 * Listener for getting temporary encryption key from the server. The actual information about the key is stored in
 * the low level {@code Session} object.
 */
public interface ICreateKeyListener {

    /**
     * The temporary encryption key has been successfully acquired from the server.
     */
    @MainThread
    void onCreateKeySucceeded();

    /**
     * Failed to acquire the temporary encryption key from the server.
     * @param throwable Failure to report.
     */
    @MainThread
    void onCreateKeyFailed(@NonNull Throwable throwable);
}
