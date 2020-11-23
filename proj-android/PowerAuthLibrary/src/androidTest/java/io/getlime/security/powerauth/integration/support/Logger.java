/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support;

import android.support.annotation.NonNull;

public class Logger {

    public static final String LOG_TAG = "PowerAuthLibraryTests";

    public static void e(@NonNull String format, Object... args) {
        String message = String.format(format, args);
        android.util.Log.e(LOG_TAG, message);
    }

    public static void d(@NonNull String format, Object... args) {
        String message = String.format(format, args);
        android.util.Log.d(LOG_TAG, message);
    }
}
