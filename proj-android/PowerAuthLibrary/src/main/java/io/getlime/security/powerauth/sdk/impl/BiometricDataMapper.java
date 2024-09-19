/*
 * Copyright 2024 Wultra s.r.o.
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
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.biometry.BiometricAuthentication;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;

import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code BiometricDataMapping} is a helper class that provides mapping for biometry-related encryption keys stored
 * in the {@link Keychain} and the {@code Android KeyStore}. Previous versions of the SDK used a shared key for all
 * {@code PowerAuthSDK} instances. This behavior was changed in the following SDK versions to use unique keys generated
 * for each instance:
 * <ul>
 *     <li>{@code 1.7.10}</li>
 *     <li>{@code 1.8.3}</li>
 *     <li>{@code 1.9.0}</li>
 * </ul>
 * This class provides a compatibility layer that allows migration from the shared key to per-instance keys. If the
 * application has already created an activation and is using the shared key, the provided mapping will point to the
 * shared key until the biometric factor is removed by the application.
 * <p>
 * Related issue: <a href="https://github.com/wultra/powerauth-mobile-sdk/issues/620">Biometrics not working on multiple
 * instances</a>.
 */
public class BiometricDataMapper {

    /**
     * The {@code Mapping} class contains information where the biometry-related encryption key is stored.
     */
    public static class Mapping {
        /**
         * If {@code true}, then this mapping points to the shared key.
         */
        public final boolean isSharedKey;
        /**
         * Key identifier (or alias) to the Android KeyStore.
         */
        public final @NonNull String keystoreId;
        /**
         * Storage key to the PowerAuth {@link Keychain}.
         */
        public final @NonNull String keychainKey;

        /**
         * Construct mapping with required parameters.
         * @param isSharedKey Information whether the key is shared.
         * @param keystoreId Key identifier (or alias) to the Android KeyStore.
         * @param keychainKey Storage key to the PowerAuth {@link Keychain}.
         */
        Mapping(boolean isSharedKey, @NonNull String keystoreId, @NonNull String keychainKey) {
            this.isSharedKey = isSharedKey;
            this.keystoreId = keystoreId;
            this.keychainKey = keychainKey;
        }
    }

    /**
     * No additional operation is required when the mapping is created.
     */
    public static final int BIO_MAPPING_NOOP = 0;
    /**
     * The mapping is required when the biometry-related encryption key is being newly crated. In this case, the mapper
     * will always return a mapping to the per-instance data.
     */
    public static final int BIO_MAPPING_CREATE_KEY = 2;
    /**
     * The mapping is required when the biometry-related encryption key is being removed. If the current mapping contains
     * the mapping to the shared, legacy key, then the mapper will return this legacy mapping. The next call to
     * {@link #getMapping(IBiometricKeystore, Context, int)} will provide a mapping to the per-instance data.
     */
    public static final int BIO_MAPPING_REMOVE_KEY = 2;

    private final ReentrantLock lock;
    private final Session session;
    private final String instanceId;
    private final String keychainStorageKey;
    private final boolean isFallbackToSharedBiometryKeyEnabled;
    private final Keychain biometricKeychain;

    /**
     * The current mapping.
     */
    private Mapping mapping;

    /**
     * Create a helper object with all required parameters.
     * @param sharedLock Instance of lock shared between multiple internal SDK objects.
     * @param session Session instance.
     * @param configuration PowerAuth SDK instance configuration.
     * @param keychainConfiguration PowerAuth SDK keychain configuration.
     * @param biometricKeychain A Keychain for storing biometry-related encryption keys.
     */
    public BiometricDataMapper(
            @NonNull ReentrantLock sharedLock,
            @NonNull Session session,
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthKeychainConfiguration keychainConfiguration,
            @NonNull Keychain biometricKeychain) {
        this.lock = sharedLock;
        this.session = session;
        this.instanceId = configuration.getInstanceId();
        this.keychainStorageKey = keychainConfiguration.getKeychainKeyBiometry();
        this.isFallbackToSharedBiometryKeyEnabled = keychainConfiguration.isFallbackToSharedBiometryKeyEnabled();
        this.biometricKeychain = biometricKeychain;
    }

    /**
     * Get the mapping for stored biometry-related encryption keys.
     * @param keyStore Instance of {@link IBiometricKeystore} object. If not provided, then function gets default, shared keystore.
     * @param context Android context object.
     * @param purpose Specify situation in which the mapping is acquired. Use {@code BIO_MAPPING_*} constants from this class.
     * @return Mapping for stored biometry-related encryption keys.
     */
    @NonNull
    public Mapping getMapping(@Nullable IBiometricKeystore keyStore, @NonNull Context context, int purpose) {
        try {
            lock.lock();

            if (keyStore == null) {
                keyStore = BiometricAuthentication.getBiometricKeystore();
            }

            // New per-instance identifiers
            final String instanceKeystoreId = instanceId;
            final String instanceKeychainKey = keychainStorageKey != null ? keychainStorageKey : instanceId;

            if (mapping == null) {
                if ((purpose != BIO_MAPPING_CREATE_KEY) && isFallbackToSharedBiometryKeyEnabled) {
                    // Legacy identifiers.
                    final String legacyKeystoreId = keyStore.getLegacySharedKeyId();
                    final String legacyKeychainKey = keychainStorageKey != null ? keychainStorageKey : PowerAuthKeychainConfiguration.KEYCHAIN_KEY_SHARED_BIOMETRY_KEY;
                    if (session.hasBiometryFactor()) {
                        // Looks like session has a biometry factor configured.
                        // if per-instance keys are set, then don't use the shared encryptor and keychain data. We already have a new
                        // setup applied on per-instance basis.
                        if (!biometricKeychain.contains(instanceKeychainKey) && !keyStore.containsBiometricKeyEncryptor(instanceKeystoreId)) {
                            if (biometricKeychain.contains(legacyKeychainKey) && keyStore.containsBiometricKeyEncryptor(legacyKeystoreId)) {
                                // Looks like keychain and keystore contains data for a shared key, so try to use such key instead.
                                mapping = new Mapping(true, legacyKeystoreId, legacyKeychainKey);
                            }
                        }
                    }
                }
                if (mapping == null) {
                    // Legacy config was not created, so create a new one, to use per-instance identifiers.
                    mapping = new Mapping(false, instanceKeystoreId, instanceKeychainKey);
                }
            }
            if (purpose == BIO_MAPPING_REMOVE_KEY) {
                // We're going to remove key. If the current config is still legacy, then we should return this legacy
                // mapping and simultaneously setup a new one.
                if (mapping.isSharedKey) {
                    final Mapping legacyMapping = mapping;
                    mapping = new Mapping(false, instanceKeystoreId, instanceKeychainKey);
                    return legacyMapping;
                }
            }
            return mapping;
        } finally {
            lock.unlock();
        }
    }
}
