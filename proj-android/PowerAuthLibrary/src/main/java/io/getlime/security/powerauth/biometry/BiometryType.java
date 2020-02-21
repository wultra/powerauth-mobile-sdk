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

package io.getlime.security.powerauth.biometry;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;

import static io.getlime.security.powerauth.biometry.BiometryType.NONE;
import static io.getlime.security.powerauth.biometry.BiometryType.GENERIC;
import static io.getlime.security.powerauth.biometry.BiometryType.FINGERPRINT;
import static io.getlime.security.powerauth.biometry.BiometryType.FACE;
import static io.getlime.security.powerauth.biometry.BiometryType.IRIS;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * The {@code BiometryType} interface provides constants that defines biometry types, supported
 * on the system. In case that device supports multiple biometry types, then {@link #GENERIC} type
 * is returned. This is due to fact, that Android doesn't provide interface to determine exact
 * type of enrolled biometry. In this case, your application should use a generic strings or icons
 * presented to the user.
 */
@Retention(SOURCE)
@IntDef({NONE, GENERIC, FINGERPRINT, FACE, IRIS})
public @interface BiometryType {

    /**
     * There's no biometry support on the device.
     */
    int NONE = 0;

    /**
     * It's not possible to determine exact type of biometry. This happens on Android 10+ systems,
     * when the device supports more than one type of biometric authentication. In this case,
     * you should use generic terms, like "Authenticate with biometry" for your UI.
     */
    int GENERIC = 1;

    /**
     * Fingerprint scanner is present on the device.
     */
    int FINGERPRINT = 2;

    /**
     * Face scanner is present on the device.
     */
    int FACE = 3;

    /**
     * Iris scanner is present on the device.
     */
    int IRIS = 4;
}
