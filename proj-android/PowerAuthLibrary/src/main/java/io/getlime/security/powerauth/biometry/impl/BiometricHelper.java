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

package io.getlime.security.powerauth.biometry.impl;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.annotation.StringRes;
import android.util.Pair;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import io.getlime.security.powerauth.R;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code BiometricHelper} class provides helper methods for PowerAuth Mobile SDK. The class
 * is supposed to be used only by the SDK itself.
 */
public class BiometricHelper {
    /**
     * Translate {@link BiometricStatus} into appropriate {@link PowerAuthErrorException}.
     *
     * @param status Status to be translated to the exception.
     * @return Exception created for the error status. If status is {@link BiometricStatus#OK},
     *         then {@code IllegalArgumentException} is produced.
     */
    public static @NonNull PowerAuthErrorException getExceptionForBiometricStatus(@BiometricStatus int status) {
        switch (status) {
            case BiometricStatus.NOT_ENROLLED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Biometric data is not enrolled on the device.");
            case BiometricStatus.NOT_SUPPORTED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Biometry is not supported on the device.");
            case BiometricStatus.NOT_AVAILABLE:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Biometry is not available. Try again later.");
            case BiometricStatus.OK:
                throw new IllegalArgumentException("Cannot get exception for success status.");
            default:
                throw new IllegalArgumentException("Unknown status.");
        }
    }

    /**
     * Translate {@link BiometricStatus} into pair of string resources, representing title and description for error dialog.
     *
     * @param status Status to be translated to error dialog resources.
     * @param resources {@link BiometricDialogResources} object with resource identifiers.
     * @return Pair of string resource identifiers, with appropriate title and description.
     */
    public static @NonNull Pair<Integer, Integer> getErrorDialogStringsForBiometricStatus(@BiometricStatus int status, @NonNull BiometricDialogResources resources) {
        final @StringRes int errorTitle;
        final @StringRes int errorDescription;
        if (status == BiometricStatus.NOT_ENROLLED) {
            // User must enroll at least one fingerprint
            errorTitle       = resources.strings.errorEnrollFingerprintTitle;
            errorDescription = resources.strings.errorEnrollFingerprintDescription;
        } else if (status == BiometricStatus.NOT_SUPPORTED) {
            // Fingerprint scanner is not supported on the authenticator
            errorTitle       = resources.strings.errorNoFingerprintScannerTitle;
            errorDescription = resources.strings.errorNoFingerprintScannerDescription;
        } else if (status == BiometricStatus.NOT_AVAILABLE) {
            // Fingerprint scanner is disabled in the system, or permission was not granted.
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        } else {
            // Fallback...
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        }
        return Pair.create(errorTitle, errorDescription);
    }

    /**
     * Create AES/CBC with PKCS7 padding cipher with given secret key.
     *
     * @param key Key to be used for encryption and decryption.
     * @return {@link Cipher} object or null in case of error.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static @Nullable Cipher createAesCipher(@NonNull SecretKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            final byte[] zero_iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            AlgorithmParameterSpec algorithmSpec = new IvParameterSpec(zero_iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
            return cipher;
        } catch (NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeyException e) {
            PA2Log.e("BiometricHelper.createAesCipher failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Encrypt provided key bytes with using cipher.
     *
     * @param keyToProtect Bytes containing key to be protected with the cipher.
     * @param cipher Cipher for the key encryption.
     * @return Encrypted bytes, or {@code null} in case of encryption error.
     */
    public static @Nullable byte[] protectKeyWithCipher(@NonNull byte[] keyToProtect, @NonNull Cipher cipher) {
        try {
            return cipher.doFinal(keyToProtect);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            PA2Log.e("BiometricHelper.protectKeyWithCipher failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Determine if the current device should explicitly fallback {@code FingerprintManager} based
     * authentication.
     *
     * @param context Android context object.
     * @return {@code true} in case that fallback to {@code FingerprintManager} is required.
     */
    public static boolean shouldFallbackToFingerprintManager(@NonNull Context context) {
        if (Build.VERSION.SDK_INT != Build.VERSION_CODES.P) {
            return false;
        }
        if (!isVendorInFallbackList(context)) {
            return false;
        }
        return isModelInPrefixList(context.getResources().getStringArray(R.array.crypto_fingerprint_fallback_prefixes));
    }

    /**
     * Determine if the current device should hide a fingerprint dialog immediately. This is required
     * for the problematic devices that display it's own, custom fingerprint dialog overlay.
     *
     * @param context Android context object.
     * @return {@code true} in case that the fingerprint dialog should be dismissed immediately.
     */
    public static boolean shouldHideFingerprintDialog(@NonNull Context context) {
        if (Build.VERSION.SDK_INT != Build.VERSION_CODES.P) {
            return false;
        }
        if (!isVendorInFallbackList(context)) {
            return false;
        }
        return isModelInPrefixList(context.getResources().getStringArray(R.array.hide_fingerprint_instantly_prefixes));
    }

    /**
     * Determine whether device manufacturer is in the list of problematic vendors and potentially
     * require some workaround for the biometric authentication.
     *
     * @param context Android context object.
     * @return {@code true} in case that vendor of the current device is problematic and needs.
     */
    private static boolean isVendorInFallbackList(@NonNull Context context) {
        final String[] vendorNames = context.getResources().getStringArray(R.array.crypto_fingerprint_fallback_vendors);
        final String vendor = Build.MANUFACTURER;
        if (vendor == null) {
            return false;
        }
        for (String vendorName : vendorNames) {
            if (vendor.equalsIgnoreCase(vendorName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether {@code Build.MODEL} matches one in the given string array.
     *
     * @param modelPrefixes String array with model prefixes.
     * @return {@code true} if the model matches one in the given string array, or {@code false} otherwise.
     */
    private static boolean isModelInPrefixList(String[] modelPrefixes) {
        final String model = Build.MODEL;
        if (model == null) {
            return false;
        }
        for (String modelPrefix : modelPrefixes) {
            if (model.startsWith(modelPrefix)) {
                return true;
            }
        }
        return false;
    }
}
