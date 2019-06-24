/*
 * Copyright 2019 Wultra s.r.o.
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

package io.getlime.security.powerauth.biometry;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;

import static io.getlime.security.powerauth.biometry.BiometricStatus.LOCKED_DOWN;
import static io.getlime.security.powerauth.biometry.BiometricStatus.NOT_ENROLLED;
import static io.getlime.security.powerauth.biometry.BiometricStatus.NOT_SUPPORTED;
import static io.getlime.security.powerauth.biometry.BiometricStatus.OK;
import static io.getlime.security.powerauth.biometry.BiometricStatus.PERMISSION_NOT_GRANTED;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * The {@code BiometricStatus} interface defines constants defining various states of biometric
 * authentication support on the system. The status may change during the application lifetime,
 * unless it's {@link #NOT_SUPPORTED}.
 */
@Retention(SOURCE)
@IntDef({OK, NOT_SUPPORTED, NOT_ENROLLED, LOCKED_DOWN, PERMISSION_NOT_GRANTED})
public @interface BiometricStatus {

    /**
     * The biometric authentication can be used right now.
     */
    int OK = 0;

    /**
     * The biometric authentication is not supported on the device, due to missing hardware or
     * missing support in the operating system.
     */
    int NOT_SUPPORTED = 1;

    /**
     * The biometric authentication is supported, but there's no biometric image enrolled in the
     * system. User has to add at least one fingerprint, or another type of biometry in the device's
     * settings.
     */
    int NOT_ENROLLED = 2;

    /**
     * The biometric authentication is locked down due to too many failed attempts to authenticate.
     */
    int LOCKED_DOWN = 3;

    /**
     * The permission to use biometry (or fingerprint) has not been granted to the application.
     */
    int PERMISSION_NOT_GRANTED = 4;
}
