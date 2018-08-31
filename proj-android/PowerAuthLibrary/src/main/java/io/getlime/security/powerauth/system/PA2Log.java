/*
 * Copyright 2017 Wultra s.r.o.
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

/**
 * Class that provides logging facility for PowerAuth SDK library.
 *
 * @author Juraj Durech
 */
public class PA2Log {

    /**
     Controls whether the PowerAuth log is enabled.
     */
    private static boolean logIsEnabled = false;
    /**
     TAG constant for our messages
     */
    private static final String LOG_TAG = "PowerAuthLibrary";

    /**
     * Controls logging from PowerAuth classes
     * @param enabled enables or disables debug logs
     */
    public static void setEnabled(boolean enabled) {
        logIsEnabled = enabled;
        if (enabled) {
            android.util.Log.d(LOG_TAG, "PA2Log is now turned on");
        }
    }
    /**
     * @return true if PowerAuth log is enabled
     */
    public static boolean isEnabled() { return logIsEnabled; }

    /**
     * Adds a formatted DEBUG log message if log is enabled.
     * @param format format string, just like for {@link java.lang.String#format String.format}
     * @param args Arguments referenced by the format specifiers in the format
     *        string.
     */
    public static void d(String format, Object... args) {
        if (logIsEnabled) {
            String message = String.format(format, args);
            android.util.Log.d(LOG_TAG, message);
        }
    }

    /**
     * Adds a formatted ERROR log message. Unlike DEBUG message calling this method always
     * produce error record.
     * @param format format string, just like for {@link java.lang.String#format String.format}
     * @param args Arguments referenced by the format specifiers in the format
     *        string.
     */
    public static void e(String format, Object... args) {
        String message = String.format(format, args);
        android.util.Log.e(LOG_TAG, message);
    }
}
