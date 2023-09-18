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

package io.getlime.security.powerauth.sdk.impl;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.CryptoUtils;

/**
 * The {@code DefaultPossessionEncryptionKeyProvider} class provides default implementation for {@link IPossessionFactorEncryptionKeyProvider}.
 */
public class DefaultPossessionFactorEncryptionKeyProvider implements IPossessionFactorEncryptionKeyProvider {

    @NonNull
    @Override
    public byte[] getPossessionFactorEncryptionKey(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId != null) {
            sb.append(androidId);
        }
        sb.append(Build.MANUFACTURER);
        sb.append(Build.MODEL);
        return normalizeStringToSignatureKek(sb.toString());
    }

    /**
     * Convert provided string into possession encryption key.
     * @param keyData Source key data for possession encryption key.
     * @return Possession encryption key calculated from key data.
     */
    @NonNull
    private static byte[] normalizeStringToSignatureKek(@NonNull String keyData) {
        return CryptoUtils.hashSha256(keyData.getBytes(), 16);
    }
}
