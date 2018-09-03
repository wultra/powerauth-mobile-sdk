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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build;
import android.support.annotation.WorkerThread;
import android.text.TextUtils;

/**
 * Class that provides detections and information about system and runtime.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Tomas Kypta
 */
public class PA2System {

    private static final String[] PATHS_SU = {
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/app/Superuser.apk",
            "/system/bin/.ext/.su",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/system/sd/xbin/su",
            "/system/su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/system/xbin/su"
    };

    private static final String[] PATHS_READ_ONLY = {
            "/",
            "/data",
            "/dev",
            "/etc",
            "/proc",
            "/sbin",
            "/sys",
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin"
    };

    private static final String[] APKS_SU = {
            // SU access
            "com.kingouser.com",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.yellowes.su",
            // SU cloaking
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloak2",
            "com.devadvance.rootcloakplus",
            "com.ramdroid.appquarantine",
            "com.zachspong.temprootremovejb",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            // root dependent apps
            "ru.meefik.busybox",
            "stericson.busybox",
            "stericson.busybox.donate",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro"
    };

    private static final String CMD_FIND_SU = "which su";
    private static final String CMD_BUSYBOX = "busybox df";
    private static final String TAGS_TEST_KEYS = "test-keys";

    /**
     * Detects if the device is rooted.
     *
     * The method is blocking - do not run on the main thread.
     *
     * @param context The context.
     * @return True if the device is rooted, false otherwise.
     */
    @WorkerThread
    public static boolean isRooted(Context context) {
        return findSuOnPaths()
                || findSuWithWhich()
                || findTagsTestKeys()
                || findWritableSystemPaths()
                || findSuApks(context);
        //        || findBusyBox() TODO consider as a separate check since there can be a FP
        // TODO consider findOtaCerts()
        // TODO consider findCyanogenmodRom() - cyanogenmod.superuser activity in com.android.settings
    }

    /**
     * Check if SU can be located on any of its standard paths.
     *
     * @return True if SU was found.
     */
    @WorkerThread
    private static boolean findSuOnPaths() {
        for (String path : PATHS_SU) {
            File su = new File(path);
            if (su.exists()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Try to find SU using shell process execution.
     *
     * @return True if SU was found.
     */
    @WorkerThread
    private static boolean findSuWithWhich() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(CMD_FIND_SU);
            String line = streamToString(process.getInputStream());
            if (!TextUtils.isEmpty(line)) {
                return true;
            }
        } catch (Exception e) {
            // test failed
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        return false;
    }

    /**
     * Check if {@link Build#TAGS} contain test keys.
     *
     * @return True if test keys were found.
     */
    private static boolean findTagsTestKeys() {
        return Build.TAGS != null && Build.TAGS.contains(TAGS_TEST_KEYS);
    }

    /**
     * Check if there is any APK indicating that the device is rooted.
     *
     * @param context The context.
     * @return True if an APK was found.
     */
    private static boolean findSuApks(Context context) {
        PackageManager packageManager = context.getPackageManager();
        for (String pkgName : APKS_SU) {
            try {
                // checking uninstalled packages because some apps hide superSU by moving them
                @SuppressWarnings("WrongConstant")
                PackageInfo packageInfo = packageManager.getPackageInfo(pkgName, 0);
                if (packageInfo != null) {
                    return true;
                }
            } catch (NameNotFoundException e) {
                // APK not found on the system
            }
        }
        return false;
    }

    /**
     * Check if the system paths are writable.
     *
     * @return True if any of the system paths is writable.
     */
    @WorkerThread
    private static boolean findWritableSystemPaths() {
        for (String path : PATHS_READ_ONLY) {
            File directory = new File(path);
            if (directory.exists() && directory.canWrite()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if BusyBox can be called.
     *
     * Warning: this test can cause false positive.
     * These devices are known to have busybox binary present in their rom:
     * - OnePlus devices
     * - Moto E
     *
     * @return True if the call to BusyBox was successfully executed.
     */
    @WorkerThread
    private static boolean findBusyBox() {
        Process process = null;
        try {
            process = new ProcessBuilder(CMD_BUSYBOX).redirectErrorStream(true).start();
            String line = streamToString(process.getInputStream());
            if (!TextUtils.isEmpty(line)) {
                return true;
            }
        } catch (Exception e) {
            // failed
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        return false;
    }

    private static String streamToString(InputStream is) throws IOException {
        Reader reader = null;
        try {
            Writer writer = new StringWriter();

            char[] buffer = new char[256];
            reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            int n;
            while ((n = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, n);
            }

            return writer.toString();
        } catch (UnsupportedEncodingException e) {
            return "";
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // not interested
                }
            }
        }
    }
}
