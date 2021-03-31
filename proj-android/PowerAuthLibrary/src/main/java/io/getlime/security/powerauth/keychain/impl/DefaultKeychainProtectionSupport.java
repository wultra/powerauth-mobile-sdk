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

import java.security.KeyStore;
import java.security.KeyStoreException;

import io.getlime.security.powerauth.keychain.KeychainProtectionSupport;
import io.getlime.security.powerauth.keychain.SymmetricKeyProvider;

/**
 * The {@code DefaultStrongBoxSupport} implements {@link KeychainProtectionSupport} interface and reflects
 * an actual support of keychain protection on the device.
 */
public class DefaultKeychainProtectionSupport implements KeychainProtectionSupport {

    private final boolean isKeyStoreEncryptionSupported;
    private final boolean isKeyStoreEncryptionEnabled;
    private final boolean isStrongBoxSupported;
    private final boolean isStrongBoxEnabled;

    /**
     * Default object constructor allowing you to configure whether StrongBox is enabled on this device.
     * @param context Android context
     * @param enabled Enable or disable StrongBox support.
     */
    public DefaultKeychainProtectionSupport(@NonNull Context context, boolean enabled) {
        this.isStrongBoxSupported = getStrongBoxIsSupported(context);
        this.isStrongBoxEnabled = enabled;
        this.isKeyStoreEncryptionSupported = getKeyStoreEncryptionIsSupported(context);
        this.isKeyStoreEncryptionEnabled = getKeyStoreEncryptionIsEnabled(context);
    }

    @Override
    public boolean isKeyStoreEncryptionSupported() {
        return isKeyStoreEncryptionSupported;
    }

    @Override
    public boolean isKeyStoreEncryptionEnabled() {
        return isKeyStoreEncryptionSupported && isKeyStoreEncryptionEnabled;
    }

    @Override
    public boolean isStrongBoxSupported() {
        return isStrongBoxSupported;
    }

    @Override
    public boolean isStrongBoxEnabled() {
        return isStrongBoxSupported && isStrongBoxEnabled;
    }

    /**
     * Get information whether StrongBox is supported on the device.
     * @param context Android context.
     * @return {@code true} if StrongBox is supported on this device.
     */
    private static boolean getStrongBoxIsSupported(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        }
        return false;
    }

    /***
     * Determine whether encryption with KeyStore backed key is supported on the current device.
     * @param context Android context.
     * @return {@code true} if KeyStore backed keys are available on the current device.
     */
    private static boolean getKeyStoreEncryptionIsSupported(@NonNull Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                return KeyStore.getInstance(SymmetricKeyProvider.ANDROID_KEY_STORE) != null;
            } catch (KeyStoreException e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Determine whether encryption with KeyStore backed key is enabled on the current device.
     * @param context Android context.
     * @return {@code true} if KeyStore backed keys are available on the current device.
     */
    private static boolean getKeyStoreEncryptionIsEnabled(@NonNull Context context) {
        final String manufacturer = Build.MANUFACTURER.toLowerCase();
        final int sdkVersion = Build.VERSION.SDK_INT;
        // Turn off encrypted keychain on all Huawei devices running on Android 6. It's quite
        // radical, but we don't have enough test devices in possession to make a better assumption
        // here. On top of that, all such devices are at the end of their lifetime.
        //
        // Related issue: https://github.com/wultra/powerauth-mobile-sdk/issues/361
        if (manufacturer.equals("huawei")) {
            return sdkVersion > Build.VERSION_CODES.M;
        }
        return true;
    }
}
