/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.keychain.fingerprint;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;

/**
 * Lightweight utility class for common fingerprint related tasks, used outside
 * the SDK (on application level).
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintUtilities {

    private static FingerprintManager fingerprintManager(@NonNull final Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        } else {
            return null;
        }
    }

    /**
     * Check if fingerprint authentication is available (HW detected and enrolled fingerprints).
     *
     * @param context Context.
     * @return true when fingerprints login available - hw available and user enrolled fingerprints, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public static boolean isFingerprintAuthAvailable(@NonNull final Context context) throws SecurityException {
        FingerprintManager mFingerprintManager = fingerprintManager(context);
        return mFingerprintManager != null && mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints();
    }

    /**
     * Check if the device has a fingerprint scanner hardware.
     *
     * @param context Context.
     * @return true when device has compatible fingerprint scanner hardware, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public static boolean hasFingerprintHardware(@NonNull final Context context) throws SecurityException {
        FingerprintManager mFingerprintManager = fingerprintManager(context);
        return mFingerprintManager != null && mFingerprintManager.isHardwareDetected();
    }

    /**
     * Check if user has some fingerprints enrolled in the device.
     *
     * @param context Context.
     * @return true when use has enrolled fingerprints, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public static boolean hasEnrolledFingerprints(@NonNull final Context context) throws SecurityException {
        FingerprintManager mFingerprintManager = fingerprintManager(context);
        return mFingerprintManager != null && mFingerprintManager.hasEnrolledFingerprints();
    }

}
