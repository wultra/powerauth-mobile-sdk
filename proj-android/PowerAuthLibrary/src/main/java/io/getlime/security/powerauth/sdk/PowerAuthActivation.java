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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;

import io.getlime.security.powerauth.core.ActivationCode;
import io.getlime.security.powerauth.core.ActivationCodeUtil;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.model.entity.ActivationType;

/**
 * The {@code PowerAuthActivation} class contains activation data required for the activation creation.
 * The object supports all types of activation currently supported in the SDK.
 */
public class PowerAuthActivation {

    final @NonNull ActivationType activationType;
    final @NonNull Map<String, String> identityAttributes;
    final @Nullable String additionalActivationOtp;
    final @Nullable String activationName;
    final @Nullable String extras;
    final @Nullable Map<String, Object> customAttributes;
    final @Nullable ActivationCode activationCode;

    /**
     * Private object constructor. Use {@link Builder} to construct an instance of the object.
     *
     * @param activationType {@link ActivationType}.
     * @param identityAttributes Identity attributes.
     * @param additionalActivationOtp String with additional activation OTP.
     * @param activationName Optional name of activation.
     * @param extras Optional extras.
     * @param customAttributes Optional custom attributes.
     * @param activationCode {@link ActivationCode} object, valid in case of regular activation.
     */
    private PowerAuthActivation(@NonNull ActivationType activationType,
                                @NonNull Map<String, String> identityAttributes,
                                @Nullable String additionalActivationOtp,
                                @Nullable String activationName,
                                @Nullable String extras,
                                @Nullable Map<String, Object> customAttributes,
                                @Nullable ActivationCode activationCode) {
        this.activationType = activationType;
        this.identityAttributes = identityAttributes;
        this.additionalActivationOtp = additionalActivationOtp;
        this.activationName = activationName;
        this.extras = extras;
        this.customAttributes = customAttributes;
        this.activationCode = activationCode;
    }

    /**
     * A builder that collects arguments to be used for the activation creation.
     */
    public static class Builder {

        private final @NonNull ActivationType activationType;
        private final @NonNull Map<String, String> identityAttributes;
        private final @Nullable String activationName;
        private final @Nullable ActivationCode activationCode;

        private @Nullable String extras;
        private @Nullable Map<String, Object> customAttributes;
        private @Nullable String additionalActivationOtp;

        /**
         * Create object with all required parameters.
         *
         * @param activationType Type of activation.
         * @param identityAttributes Identity attributes.
         * @param activationName Optional name of activation.
         * @param activationCode {@link ActivationCode} object, valid in case of regular activation.
         */
        private Builder(@NonNull ActivationType activationType,
                        @NonNull Map<String, String> identityAttributes,
                        @Nullable String activationName,
                        @Nullable ActivationCode activationCode) {
            this.activationType = activationType;
            this.identityAttributes = identityAttributes;
            this.activationName = activationName;
            this.activationCode = activationCode;
        }

        /**
         * Construct a {@link Builder} object for a regular activation with activation code.
         * The activation code may contain an optional signature part, in case that it is scanned
         * from QR code.
         *
         * The activation's name parameter is optional, but recommended to set. You can use the value obtained from
         * {@code Settings.System.getString(getContentResolver(), "device_name")} or let the user set the name.
         * The name of activation will be associated with an activation record on PowerAuth Server.
         *
         * @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
         * @param activationName Activation name to be used for the activation.
         * @return {@link Builder} instance.
         * @throws PowerAuthErrorException In case that activation code is invalid.
         */
        public static @NonNull Builder activation(@NonNull String activationCode, @Nullable String activationName) throws PowerAuthErrorException {
            final ActivationCode code = ActivationCodeUtil.parseFromActivationCode(activationCode);
            if (code == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_CODE, "Invalid activation code");
            }
            final Map<String, String> identityAttributes = new HashMap<>(1);
            identityAttributes.put("code", code.activationCode);
            return new Builder(ActivationType.CODE, identityAttributes, activationName, code);
        }

        /**
         * Construct a {@link Builder} object with an identity attributes for the custom activation purposes.
         *
         * The activation's name parameter is optional, but recommended to set. You can use the value obtained from
         * {@code Settings.System.getString(getContentResolver(), "device_name")} or let the user set the name.
         * The name of activation will be associated with an activation record on PowerAuth Server.
         *
         * @param identityAttributes Custom activation parameters that are used to prove identity of a user.
         * @param activationName Activation name to be used for the activation.
         * @return {@link Builder} instance.
         * @throws PowerAuthErrorException In case that identity attributes map is empty.
         */
        public static @NonNull Builder customActivation(@NonNull Map<String, String> identityAttributes, @Nullable String activationName) throws PowerAuthErrorException {
            if (identityAttributes.isEmpty()) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_CODE, "Empty identity attributes");
            }
            return new Builder(ActivationType.CUSTOM, identityAttributes, activationName, null);
        }

        /**
         * Construct a {@link Builder} object with recovery activation code and PUK.
         *
         * The activation's name parameter is optional, but recommended to set. You can use the value obtained from
         * {@code Settings.System.getString(getContentResolver(), "device_name")} or let the user set the name.
         * The name of activation will be associated with an activation record on PowerAuth Server.
         *
         * @param recoveryCode Recovery code, obtained either via QR code scanning or by manual entry.
         * @param puk PUK obtained by manual entry.
         * @param activationName Activation name to be used for the activation.
         * @return {@link Builder} instance.
         * @throws PowerAuthErrorException In case that recovery code or PUK is invalid.
         */
        public static @NonNull Builder recoveryActivation(@NonNull String recoveryCode, @NonNull String puk, @Nullable String activationName) throws PowerAuthErrorException {
            final ActivationCode code = ActivationCodeUtil.parseFromRecoveryCode(recoveryCode);
            if (code == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_CODE, "Invalid recovery code");
            }
            if (!ActivationCodeUtil.validateRecoveryPuk(puk)) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_CODE, "Invalid recovery PUK");
            }
            final Map<String, String> identityAttributes = new HashMap<>(2);
            identityAttributes.put("recoveryCode", code.activationCode);
            identityAttributes.put("puk", puk);
            return new Builder(ActivationType.RECOVERY, identityAttributes, activationName, null);
        }

        /**
         * Set extra attributes of the activation, used for application specific purposes (for example, info about the client
         * device or system). This extras string will be associated with the activation record on PowerAuth Server.
         *
         * @param extras String with extra attributes
         * @return This value will never be {@code null}.
         */
        public @NonNull Builder setExtras(@Nullable String extras) {
            this.extras = extras;
            return this;
        }

        /**
         * Set custom attributes dictionary that are processed on Intermediate Server Application.
         * Note that this custom data will not be associated with the activation record on PowerAuth Server.
         *
         * @param customAttributes Custom attributes. The provided map must contain only objects that can be serialized to JSON.
         * @return This value will never be {@code null}.
         */
        public @NonNull Builder setCustomAttributes(@Nullable Map<String, Object> customAttributes) {
            this.customAttributes = customAttributes;
            return this;
        }

        /**
         * Sets an additional activation OTP that can be used only with a regular activation, by activation code.
         *
         * @param additionalActivationOtp Additional activation OTP.
         * @return This value will never be {@code null}.
         */
        public @NonNull Builder setAdditionalActivationOtp(@NonNull String additionalActivationOtp) {
            this.additionalActivationOtp = additionalActivationOtp;
            return this;
        }

        /**
         * Creates {@link PowerAuthActivation}.
         *
         * @return Instance of {@link PowerAuthActivation}.
         * @throws PowerAuthErrorException In case of invalid combination of parameters.
         */
        public PowerAuthActivation build() throws PowerAuthErrorException {
            // Check whether an additional activation OTP is used for the right activation type.
            if (additionalActivationOtp != null) {
                if (additionalActivationOtp.isEmpty()) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA, "Additional activation OTP is empty");
                }
                if (activationType != ActivationType.CODE) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA, "Only regular activation can be used with additional activation OTP");
                }
            }
            // Construct PowerAuthActivation object.
            return new PowerAuthActivation(
                    activationType,
                    identityAttributes,
                    additionalActivationOtp,
                    activationName,
                    extras,
                    customAttributes,
                    activationCode
            );
        }
    }
}
