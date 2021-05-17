/*
 * Copyright 2021 Wultra s.r.o.
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

import android.os.Build;
import androidx.annotation.NonNull;

/**
 * Class that provides information about system and runtime.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Tomas Kypta
 */
public class PowerAuthSystem {

    /**
     * Return platform name.
     *
     * @return "Android" constant as a platform name.
     */
    public static @NonNull String getPlatform() {
        return "Android";
    }

    /**
     * Return device model information.
     *
     * @return Combination of device's manufacturer and model.
     */
    public static @NonNull String getDeviceInfo() {
        String manufacturer = Build.MANUFACTURER;
        String model = Build.MODEL;
        if (model.toLowerCase().startsWith(manufacturer.toLowerCase())) {
            return capitalizeString(model);
        }
        return capitalizeString(manufacturer) + " " + model;
    }

    /**
     * Helper method that capitalize given string.
     * @param s String to capitalize.
     * @return Capitalized string.
     */
    private static String capitalizeString(String s) {
        if (s == null || s.length() == 0) {
            return "";
        }
        char first = s.charAt(0);
        if (Character.isUpperCase(first)) {
            return s;
        }
        return Character.toUpperCase(first) + s.substring(1);
    }
}
