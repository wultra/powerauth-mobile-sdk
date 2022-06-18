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

package io.getlime.security.powerauth.networking.response;

import android.content.Context;
import androidx.annotation.NonNull;

/**
 * Strategy for getting encryption key that protects possession factor key. The provided key
 * should be calculated from data unique for the device, such as ANDROID_ID.
 *
 * The interface is deprecated since 1.7.0. If you still use it, then please contact us that
 * we can provide a new solution for you.
 */
@Deprecated // 1.7.0
public interface IFetchKeysStrategy {

    /**
     * Return encryption key that protects possession factor key.
     * @param context Android context.
     * @return String that will be reinterpret into encryption key that protects possession factor key.
     */
    @NonNull String getPossessionUnlockKey(@NonNull Context context);
}
