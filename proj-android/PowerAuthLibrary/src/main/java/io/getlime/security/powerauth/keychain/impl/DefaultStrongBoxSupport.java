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

package io.getlime.security.powerauth.keychain.impl;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.support.annotation.NonNull;

import io.getlime.security.powerauth.keychain.StrongBoxSupport;

/**
 * The {@code DefaultStrongBoxSupport} implements {@link StrongBoxSupport} interface and reflects
 * an actual support of StrongBox on device.
 */
public class DefaultStrongBoxSupport implements StrongBoxSupport {

    private final boolean isSupported;
    private final boolean isEnabled;

    /**
     * Default object constructor allowing you to configure whether StrongBox is enabled on this device.
     * @param context Android context
     * @param enabled Enable or disable StrongBox support.
     */
    public DefaultStrongBoxSupport(@NonNull Context context, boolean enabled) {
        this.isSupported = getIsSupported(context);
        this.isEnabled = enabled;
    }

    /**
     * Get information whether StrongBox is supported on the device.
     * @param context Android context.
     * @return {@code true} if StrongBox is supported on this device.
     */
    private static boolean getIsSupported(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        }
        return false;
    }

    @Override
    public boolean isStrongBoxSupported() {
        return isSupported;
    }

    @Override
    public boolean isStrongBoxEnabled() {
        return isSupported && isEnabled;
    }
}
