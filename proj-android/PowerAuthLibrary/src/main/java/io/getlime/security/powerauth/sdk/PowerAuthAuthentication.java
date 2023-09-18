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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Class representing a multi-factor authentication object.
 */
public class PowerAuthAuthentication {
    /**
     * If set, then the biometry factor will be used.
     */
    private final @Nullable byte[] useBiometry;
    /**
     * If set, then the password will be used.
     */
    private final @Nullable Password password;
    /**
     * Optional custom possession key.
     */
    private final @Nullable byte[] overriddenPossessionKey;

    /**
     * Contains {@code true} if authentication object should be used to persist activation, {@code false}
     * if object is for signature calculation or {@code null} if this is a legacy object with no usage
     * specified.
     */
    private final Boolean persistActivation;

    /**
     * Construct object with desired combination of factors. Such authentication object can be used
     * either to persist activation and for the signature calculation.
     *
     * Note that you should prefer static construction functions instead of this constructor, unless
     * you have a special reason for it.
     *
     * @param persistActivation If true, then authentication can be used to persist activation.
     * @param password If set, then knowledge factor will be used to persist activation or signature calculation.
     * @param biometryFactorRelatedKey If set, then biometry factor will be used to persist activation or the signature calculation.
     * @param overriddenPossessionKey Custom possession factor related key.
     */
    PowerAuthAuthentication(
            Boolean persistActivation,
            @Nullable Password password,
            @Nullable byte[] biometryFactorRelatedKey,
            @Nullable byte[] overriddenPossessionKey) {
        this.useBiometry = biometryFactorRelatedKey;
        this.password = password;
        this.overriddenPossessionKey = overriddenPossessionKey;
        this.persistActivation = persistActivation;
    }

    // Persist activation

    /**
     * Construct authentication object to persist activation with password.
     * @param password Password to set for new activation.
     * @return Authentication object constructed to persist activation with the password.
     */
    public static PowerAuthAuthentication persistWithPassword(@NonNull String password) {
        return new PowerAuthAuthentication(true, new Password(password), null, null);
    }

    /**
     * Construct authentication object to persist activation with password and custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed to persist activation with password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication persistWithPassword(@NonNull String password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, new Password(password), null, overriddenPossessionKey);
    }

    /**
     * Construct authentication object to persist activation with password and with biometry.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @return Authentication object constructed to persist activation with password and biometry.
     */
    public static PowerAuthAuthentication persistWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey) {
        return new PowerAuthAuthentication(true, new Password(password), biometryFactorRelatedKey, null);
    }

    /**
     * Construct authentication object to persist activation with password, biometry and with custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed to persist activation with password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication persistWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, new Password(password), biometryFactorRelatedKey, overriddenPossessionKey);
    }

    // core/Password variants

    /**
     * Construct authentication object to persist activation with password.
     * @param password Password to set for new activation.
     * @return Authentication object constructed to persist activation with the password.
     */
    public static PowerAuthAuthentication persistWithPassword(@NonNull Password password) {
        return new PowerAuthAuthentication(true, password, null, null);
    }

    /**
     * Construct authentication object to persist activation with password and custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed to persist activation and password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication persistWithPassword(@NonNull Password password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, password, null, overriddenPossessionKey);
    }

    /**
     * Construct authentication object to persist activation with password and with biometry.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @return Authentication object constructed to persist activation with password and biometry.
     */
    public static PowerAuthAuthentication persistWithPasswordAndBiometry(@NonNull Password password, @NonNull byte[] biometryFactorRelatedKey) {
        return new PowerAuthAuthentication(true, password, biometryFactorRelatedKey, null);
    }

    /**
     * Construct authentication object to persist activation with password, biometry and with custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed to persist activation with password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication persistWithPasswordAndBiometry(@NonNull Password password, @NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, password, biometryFactorRelatedKey, overriddenPossessionKey);
    }


    // Commit activation (deprecated)

    /**
     * Construct authentication object for activation commit with password.
     * @param password Password to set for new activation.
     * @return Authentication object constructed for commit activation with the password.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPassword(@NonNull String password) {
        return persistWithPassword(password);
    }

    /**
     * Construct authentication object for activation commit with password and custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation and password, with using custom key for the possession factor.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPassword(@NonNull String password, @NonNull byte[] overriddenPossessionKey) {
        return persistWithPassword(password, overriddenPossessionKey);
    }

    /**
     * Construct authentication object for activation commit with password and with biometry.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @return Authentication object constructed for commit activation with password and biometry.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey) {
        return persistWithPasswordAndBiometry(password, biometryFactorRelatedKey);
    }

    /**
     * Construct authentication object for activation commit with password, biometry and with custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation with password, with using custom key for the possession factor.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return persistWithPasswordAndBiometry(password, biometryFactorRelatedKey, overriddenPossessionKey);
    }

    // core/Password variants

    /**
     * Construct authentication object for activation commit with password.
     * @param password Password to set for new activation.
     * @return Authentication object constructed for commit activation with the password.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPassword(@NonNull Password password) {
        return persistWithPassword(password);
    }

    /**
     * Construct authentication object for activation commit with password and custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation and password, with using custom key for the possession factor.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPassword(@NonNull Password password, @NonNull byte[] overriddenPossessionKey) {
        return persistWithPassword(password, overriddenPossessionKey);
    }

    /**
     * Construct authentication object for activation commit with password and with biometry.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @return Authentication object constructed for commit activation with password and biometry.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull Password password, @NonNull byte[] biometryFactorRelatedKey) {
        return persistWithPasswordAndBiometry(password, biometryFactorRelatedKey);
    }

    /**
     * Construct authentication object for activation commit with password, biometry and with custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation with password, with using custom key for the possession factor.
     */
    @Deprecated // 1.8.0
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull Password password, @NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return persistWithPasswordAndBiometry(password, biometryFactorRelatedKey, overriddenPossessionKey);
    }

    // Authenticate

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession factor only.
     * @return Authentication object constructed to calculate signature with possession factor only.
     */
    public static PowerAuthAuthentication possession() {
        return new PowerAuthAuthentication(false, null, null, null);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession factor only, with using custom possession key.
     * @param overriddenPossessionKey Custom possession key to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession factor with custom possession key.
     */
    public static PowerAuthAuthentication possession(@NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(false, null, null, overriddenPossessionKey);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and knowledge factors.
     * @param password Password to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and knowledge factors.
     */
    public static PowerAuthAuthentication possessionWithPassword(@NonNull String password) {
        return new PowerAuthAuthentication(false, new Password(password), null, null);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and knowledge factors, with using custom possession key.
     * @param password Password to use for the signature calculation.
     * @param overriddenPossessionKey Custom possession key to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and knowledge factors, with using custom possession key.
     */
    public static PowerAuthAuthentication possessionWithPassword(@NonNull String password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(false, new Password(password), null, overriddenPossessionKey);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and biometry factors.
     * @param biometryFactorRelatedKey Biometry key data to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and biometry factors
     */
    public static PowerAuthAuthentication possessionWithBiometry(@NonNull byte[] biometryFactorRelatedKey) {
        return new PowerAuthAuthentication(false, null, biometryFactorRelatedKey, null);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and biometry factors, with using custom possession key.
     * @param biometryFactorRelatedKey Biometry key data to use for the signature calculation.
     * @param overriddenPossessionKey Custom possession key to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and biometry factors, with using custom possession key.
     */
    public static PowerAuthAuthentication possessionWithBiometry(@NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(false, null, biometryFactorRelatedKey, overriddenPossessionKey);
    }

    // core/Password variants
    
    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and knowledge factors.
     * @param password Password to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and knowledge factors.
     */
    public static PowerAuthAuthentication possessionWithPassword(@NonNull Password password) {
        return new PowerAuthAuthentication(false, password, null, null);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and knowledge factors, with using custom possession key.
     * @param password Password to use for the signature calculation.
     * @param overriddenPossessionKey Custom possession key to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and knowledge factors, with using custom possession key.
     */
    public static PowerAuthAuthentication possessionWithPassword(@NonNull Password password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(false, password, null, overriddenPossessionKey);
    }

    /**
     * @return Biometry key data, or nil if biometry factor is not used.
     */
    @Nullable
    public byte[] getBiometryFactorRelatedKey() {
        return useBiometry;
    }

    /**
     * @return Password to be used for knowledge factor, or nil if knowledge factor is not used.
     */
    @Nullable
    public Password getPassword() {
        return password;
    }

    /**
     * @return If non-null, then custom key is specified for the possession factor.
     */
    @Nullable
    public byte[] getOverriddenPossessionKey() {
        return overriddenPossessionKey;
    }

    // Internal interfaces

    /**
     * Calculate numeric value representing a combination of used factors.
     * @return Numeric value representing a combination of factors.
     */
    int getSignatureFactorsMask() {
        int factors = 1;
        if (password != null) {
            factors |= 2;
        }
        if (useBiometry != null) {
            factors |= 4;
        }
        return factors;
    }

    /**
     * Validate usage of PowerAuthAuthentication object. If something doesn't match, then function
     * print warning to the debug console.
     * @param forPersist If true, then activation persist is expected.
     * @return false if object is created for the different purpose or is legacy constructed.
     */
    boolean validateAuthenticationUsage(boolean forPersist) {
        boolean result = validateAuthenticationUsageImpl(forPersist);
        if (!result && strictAuthenticationUsageValidation) {
            throw new IllegalArgumentException("Invalid PowerAuthAuthentication object provided");
        }
        return result;
    }

    /**
     * If set to true, then validateAuthenticationUsage() throws IllegalArgumentException().
     */
    private static boolean strictAuthenticationUsageValidation = false;

    /**
     * Enable or disable strict mode for {@link #validateAuthenticationUsage(boolean)} method.
     * If strict mode is enabled, then validation throws an error in case that validation fails.
     * This is useful only for PowerAuth SDK unit and integration testing.
     *
     * @param strict Enable or disable strict mode.
     */
    static void setStrictValidateAuthenticationUsage(boolean strict) {
        strictAuthenticationUsageValidation = strict;
    }

    /**
     * Validate usage of PowerAuthAuthentication object. If something doesn't match, then function
     * print warning to the debug console.
     * @param forPersist If true, then activation persist is expected.
     * @return false if object is created for the different purpose or is legacy constructed.
     */
    private boolean validateAuthenticationUsageImpl(boolean forPersist) {
        if (persistActivation == null) {
            PowerAuthLog.w("Using PowerAuthAuthentication object created with legacy constructor.");
            return false;
        } else {
            if (persistActivation != forPersist) {
                if (forPersist) {
                    PowerAuthLog.w("Using PowerAuthAuthentication object for a different purpose. The object to persist activation is expected.");
                } else {
                    PowerAuthLog.w("Using PowerAuthAuthentication object for a different purpose. The object for signature calculation is expected.");
                }
                return false;
            }
        }
        return true;
    }
}
