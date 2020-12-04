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

import androidx.annotation.NonNull;

/**
 * The {@code BiometricKeyData} class contains result from the biometric authentication in case that
 * authentication succeeded.
 */
public class BiometricKeyData {

    private final @NonNull byte[] dataToSave;
    private final @NonNull byte[] derivedData;
    private final boolean newKey;

    /**
     * Construct object with data to save, derived key and flag that this is a new key generated.
     *
     * @param dataToSave Data that should be stored to the persistent storage in case that this is a new key.
     * @param derivedData Data derived from raw key bytes provided in biometric authentication request.
     * @param isNewKey Is {@code true} in case that this is a new key generated.
     */
    public BiometricKeyData(@NonNull byte[] dataToSave, @NonNull byte[] derivedData, boolean isNewKey) {
        this.dataToSave = dataToSave;
        this.derivedData = derivedData;
        this.newKey = isNewKey;
    }

    /**
     * @return Data that should be stored to the persistent storage in case that this is a new key.
     */
    public @NonNull byte[] getDataToSave() {
        return dataToSave;
    }

    /**
     * @return Data derived from raw key bytes provided in biometric authentication request.
     */
    public @NonNull byte[] getDerivedData() {
        return derivedData;
    }

    /**
     * @return Is {@code true} in case that this is a new key generated.
     */
    public boolean isNewKey() {
        return newKey;
    }
}
