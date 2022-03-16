/*
 * Copyright 2022 Wultra s.r.o.
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
import android.util.Base64;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SessionSetup;
import io.getlime.security.powerauth.networking.response.IFetchKeysStrategy;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class DefaultPossessionFactorEncryptionKeyProviderTests {

    private Context context;
    private Session session;

    @Before
    public void setUp() {
        String appKey = Base64.encodeToString(CryptoUtils.randomBytes(16), Base64.NO_WRAP);
        String appSecret = Base64.encodeToString(CryptoUtils.randomBytes(16), Base64.NO_WRAP);
        String pubKey = Base64.encodeToString(CryptoUtils.randomBytes(33), Base64.NO_WRAP);
        context = InstrumentationRegistry.getInstrumentation().getContext();
        session = new Session(new SessionSetup(appKey, appSecret, pubKey, 0, null));
    }

    @Test
    public void testDefaultPossessionFactorEncryptionKeyProvider() {
        final IPossessionFactorEncryptionKeyProvider provider = new DefaultPossessionFactorEncryptionKeyProvider();
        byte[] possessionKek = provider.getPossessionFactorEncryptionKey(context);
        assertNotNull(possessionKek);
        assertEquals(16, possessionKek.length);

        byte[] oldPossessionKek = session.normalizeSignatureUnlockKeyFromData(getOldPossessionUnlockKeyData().getBytes());
        assertArrayEquals(oldPossessionKek, possessionKek);
    }

    @Test
    public void testWrapperForDeprecatedFetchKeysStrategy() {
        final IPossessionFactorEncryptionKeyProvider provider = DefaultPossessionFactorEncryptionKeyProvider.createFromFetchKeyStrategy(new IFetchKeysStrategy() {
            @NonNull
            @Override
            public String getPossessionUnlockKey(@NonNull Context context) {
                return getOldPossessionUnlockKeyData();
            }
        });

        byte[] possessionKek = provider.getPossessionFactorEncryptionKey(context);
        assertNotNull(possessionKek);
        assertEquals(16, possessionKek.length);

        byte[] oldPossessionKek = session.normalizeSignatureUnlockKeyFromData(getOldPossessionUnlockKeyData().getBytes());
        assertArrayEquals(oldPossessionKek, possessionKek);
    }

    /**
     * Original implementation for DefaultFetchKeysStrategy.getPossessionUnlockKey().
     * @return String representation of possession KEK.
     */
    @NonNull String getOldPossessionUnlockKeyData() {
        StringBuilder sb = new StringBuilder();
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId != null) {
            sb.append(androidId);
        }
        sb.append(Build.MANUFACTURER);
        sb.append(Build.MODEL);
        return sb.toString();
    }
}
