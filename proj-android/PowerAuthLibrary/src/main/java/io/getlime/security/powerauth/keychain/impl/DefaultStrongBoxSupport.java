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
import io.getlime.security.powerauth.system.PA2System;

public class DefaultStrongBoxSupport implements StrongBoxSupport {

    private final @NonNull Context context;

    public DefaultStrongBoxSupport(@NonNull Context context) {
        this.context = context;
    }

    @Override
    public boolean isStrongBoxSupported() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        }
        return false;
    }

    @Override
    public boolean isStrongBoxEnabled() {
        if (!isStrongBoxSupported()) {
            return false;
        }
        final String deviceInfo = PA2System.getDeviceInfo().toLowerCase();
        if (deviceInfo.startsWith("google pixel")) {
            return false;
        }
        return true;
    }
}
