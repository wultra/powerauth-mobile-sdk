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

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import io.getlime.security.powerauth.BuildConfig;

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
     * Build default value for "User-Agent" HTTP request header. The value is composed as
     * "APP-PACKAGE/APP-VERSION PowerAuth2/PA-VERSION (Android OS-VERSION, DEVICE-INFO)", for example:
     * "com.test.app/1.0 PowerAuth2/1.7.0 (Android 11.0.0, SM-A525F)".
     * @param context Android context.
     * @return Default value for User-Agent HTTP request header.
     */
    public static @NonNull String getDefaultUserAgent(@NonNull Context context) {
        // Get basic info about library
        final String libraryInfo = "PowerAuth2/" + BuildConfig.LIBRARY_VERSION_NAME + " (Android " + Build.VERSION.RELEASE + ", " + getDeviceInfo() + ")";
        // Get info about application
        context = context.getApplicationContext();
        PackageManager pm = context.getPackageManager();
        String pkgName = context.getPackageName();
        PackageInfo pkgInfo;
        try {
            pkgInfo = pm.getPackageInfo(pkgName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            pkgInfo = null;
        }

        if (pkgInfo != null) {
            String pkgVer = pkgInfo.versionName;
            if (pkgVer != null) {
                return pkgName + "/" + pkgVer + " " + libraryInfo;
            }
        }
        return libraryInfo;
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
