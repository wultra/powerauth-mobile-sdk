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

import androidx.annotation.NonNull;

/**
 * Interface for getting encryption key that protects possession factor key. The provided key
 * should be calculated from data unique for the device, such as ANDROID_ID.
 */
public interface IPossessionFactorEncryptionKeyProvider {
    /**
     * Return encryption key that protects possession factor key.
     * @param context Android context.
     * @return 16 bytes long encryption key that protects possession factor key.
     */
    @NonNull byte[] getPossessionFactorEncryptionKey(@NonNull Context context);
}
