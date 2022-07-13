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
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Class representing a multi-factor authentication object.
 */
@SuppressWarnings("deprecation") // @Deprecated // 1.7.0
public class PowerAuthAuthentication {

    /**
     * Accessing field directly is now deprecated. Please use appropriate static method to construct
     * {@code PowerAuthAuthentication} object.
     *
     * The property is ignored
     */
    @Deprecated // 1.7.0
    public boolean usePossession;
    /**
     * Accessing field directly is now deprecated. Please use appropriate static method to construct
     * {@code PowerAuthAuthentication} object.
     */
    @Deprecated // 1.7.0
    public @Nullable byte[] useBiometry;
    /**
     * Accessing field directly is now deprecated. Please use appropriate static method to construct
     * {@code PowerAuthAuthentication} object.
     */
    @Deprecated // 1.7.0
    public @Nullable String usePassword;
    /**
     * Accessing field directly is now deprecated. Please use appropriate static method to construct
     * {@code PowerAuthAuthentication} object.
     */
    @Deprecated // 1.7.0
    public @Nullable byte[] overriddenPossessionKey;


    private final Boolean activationCommit;

    /**
     * Constructor that allows you alter factors after the object is created.
     *
     * Object constructor is now deprecated, please use appropriate static method to construct
     * {@code PowerAuthAuthentication} object.
     */
    @Deprecated // 1.7.0
    public PowerAuthAuthentication() {
        this.usePossession = false;
        this.useBiometry = null;
        this.usePassword = null;
        this.overriddenPossessionKey = null;
        this.activationCommit = null;
    }

    /**
     * Construct object with desired combination of factors. Such authentication object can be used
     * either for activation commit and for the signature calculation.
     *
     * Note that you should prefer static construction functions instead of this constructor, unless
     * you have a special reason for it.
     *
     * @param activationCommit If true, then authentication can be used for activation commit.
     * @param password If set, then knowledge factor will be used for activation commit or signature calculation.
     * @param biometryFactorRelatedKey If set, then biometry factor will be used for activation commit or the signature calculation.
     * @param overriddenPossessionKey Custom possession factor related key.
     */
    PowerAuthAuthentication(
            boolean activationCommit,
            @Nullable String password,
            @Nullable byte[] biometryFactorRelatedKey,
            @Nullable byte[] overriddenPossessionKey) {
        this.usePossession = true;
        this.useBiometry = biometryFactorRelatedKey;
        this.usePassword = password;
        this.overriddenPossessionKey = overriddenPossessionKey;
        this.activationCommit = activationCommit;
    }

    // Commit activation

    /**
     * Construct authentication object for activation commit with password.
     * @param password Password to set for new activation.
     * @return Authentication object constructed for commit activation with the password.
     */
    public static PowerAuthAuthentication commitWithPassword(@NonNull String password) {
        return new PowerAuthAuthentication(true, password, null, null);
    }

    /**
     * Construct authentication object for activation commit with password and custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation and password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication commitWithPassword(@NonNull String password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, password, null, overriddenPossessionKey);
    }

    /**
     * Construct authentication object for activation commit with password and with biometry.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @return Authentication object constructed for commit activation with password and biometry.
     */
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey) {
        return new PowerAuthAuthentication(true, password, biometryFactorRelatedKey, null);
    }

    /**
     * Construct authentication object for activation commit with password, biometry and with custom key for the possession factor.
     * @param password Password to set for new activation.
     * @param biometryFactorRelatedKey Biometry factor related key to set for new activation.
     * @param overriddenPossessionKey Custom possession key to set for new activation.
     * @return Authentication object constructed for commit activation with password, with using custom key for the possession factor.
     */
    public static PowerAuthAuthentication commitWithPasswordAndBiometry(@NonNull String password, @NonNull byte[] biometryFactorRelatedKey, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(true, password, biometryFactorRelatedKey, overriddenPossessionKey);
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
        return new PowerAuthAuthentication(false, password, null, null);
    }

    /**
     * Construct authentication object for signature calculation purposes. The signature is calculated with possession and knowledge factors, with using custom possession key.
     * @param password Password to use for the signature calculation.
     * @param overriddenPossessionKey Custom possession key to use for the signature calculation.
     * @return Authentication object constructed to calculate signature with possession and knowledge factors, with using custom possession key.
     */
    public static PowerAuthAuthentication possessionWithPassword(@NonNull String password, @NonNull byte[] overriddenPossessionKey) {
        return new PowerAuthAuthentication(false, password, null, overriddenPossessionKey);
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

    /**
     * Biometry key data, or nil if biometry factor is not used.
     */
    @Nullable
    public byte[] getBiometryFactorRelatedKey() {
        return useBiometry;
    }

    /**
     * Password to be used for knowledge factor, or nil if knowledge factor is not used.
     */
    @Nullable
    public String getPassword() {
        return usePassword;
    }

    /**
     * If non-null, then custom key is specified for the possession factor.
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
        int factors = 0;
        if (usePossession) {
            factors |= 1;
        }
        if (usePassword != null) {
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
     * @param forCommit If true, then activation commit is expected.
     * @return false if object is created for the different purpose or is legacy constructed.
     */
    boolean validateAuthenticationUsage(boolean forCommit) {
        if (activationCommit == null) {
            PowerAuthLog.e("WARNING: Using PowerAuthAuthentication object created with legacy constructor.");
            return false;
        } else {
            if (activationCommit != forCommit) {
                if (forCommit) {
                    PowerAuthLog.e("WARNING: Using PowerAuthAuthentication object for a different purpose. The object for activation commit is expected.");
                } else {
                    PowerAuthLog.e("WARNING: Using PowerAuthAuthentication object for a different purpose. The object for signature calculation is expected.");
                }
                return false;
            }
        }
        return true;
    }
}
