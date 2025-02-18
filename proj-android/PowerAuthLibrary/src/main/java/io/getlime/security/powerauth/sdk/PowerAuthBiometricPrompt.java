/*
 * Copyright 2025 Wultra s.r.o.
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
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

/**
 * The {@code PowerAuthBiometricPrompt} class contains information required for displaying the biometric authentication
 * prompt.
 */
public class PowerAuthBiometricPrompt {
    /**
     * Required dialog's title.
     */
    private final @NonNull CharSequence title;
    /**
     * Optional dialog's subtitle.
     */
    private final @Nullable CharSequence subtitle;
    /**
     * Required dialog's description.
     */
    private final @NonNull CharSequence description;
    /**
     * Parent fragment activity. If null, then {@link #fragment} must be set.
     */
    private final @Nullable FragmentActivity fragmentActivity;
    /**
     * Parent fragment. If null then {@link #fragmentActivity} must be set.
     */
    private final @Nullable Fragment fragment;
    /**
     * If true, then this prompt contains dummy prompt data.
     */
    private final boolean isDummy;

    /**
     * Create biometric prompt with provided title and description.
     * @param fragment Parent fragment.
     * @param title Biometric prompt's title.
     * @param description Biometric prompt's description.
     * @return {@link PowerAuthBiometricPrompt} created with given title and description.
     */
    @NonNull
    public static PowerAuthBiometricPrompt prompt(@NonNull Fragment fragment, @NonNull CharSequence title, @NonNull CharSequence description) {
        return new Builder(fragment)
                .setTitle(title)
                .setDescription(description)
                .build();
    }

    /**
     * Create biometric prompt with provided title and description.
     * @param fragmentActivity Parent fragment activity.
     * @param title Biometric prompt's title.
     * @param description Biometric prompt's description.
     * @return {@link PowerAuthBiometricPrompt} created with given title and description.
     */
    @NonNull
    public static PowerAuthBiometricPrompt prompt(@NonNull FragmentActivity fragmentActivity, @NonNull CharSequence title, @NonNull CharSequence description) {
        return new Builder(fragmentActivity)
                .setTitle(title)
                .setDescription(description)
                .build();
    }

    /**
     * Create instance of dummy biometric prompt, allowed to be used only for the biometric key setup and if {@link PowerAuthBiometricConfiguration#isAuthenticateOnBiometricKeySetup()}
     * configuration is set to {@code false}. In other words, if biometric key setup doesn't require actual biometric authentication, then you can use this dummy
     * prompt to indicate that biometric factor should be used.
     * <p>
     * This can simplify your code in two typical scenarios:
     * <ul>
     *     <li>When you're going to persist the activation</li>
     *     <li>When you're going to add biometric factor to the existing activation.</li>
     * </ul>
     *
     * @param fragment Parent fragment.
     * @return Biometric prompt allowed to be used only for the biometric key setup and if {@link PowerAuthBiometricConfiguration#isAuthenticateOnBiometricKeySetup()}
     * configuration is set to {@code false}.
     */
    @NonNull
    public static PowerAuthBiometricPrompt noPromptForBiometricKeySetup(@NonNull Fragment fragment) {
        return new Builder(fragment).setDummy().build();
    }

    /**
     * Create instance of dummy biometric prompt, allowed to be used only for the biometric key setup and if {@link PowerAuthBiometricConfiguration#isAuthenticateOnBiometricKeySetup()}
     * configuration is set to {@code false}. In other words, if biometric key setup doesn't require actual biometric authentication, then you can use this dummy
     * prompt to indicate that biometric factor should be used.
     * <p>
     * This can simplify your code in two typical scenarios:
     * <ul>
     *     <li>When you're going to persist the activation</li>
     *     <li>When you're going to add biometric factor to the existing activation.</li>
     * </ul>
     *
     * @param fragmentActivity Parent fragment activity.
     * @return Biometric prompt allowed to be used only for the biometric key setup and if {@link PowerAuthBiometricConfiguration#isAuthenticateOnBiometricKeySetup()}
     * configuration is set to {@code false}.
     */
    @NonNull
    public static PowerAuthBiometricPrompt noPromptForBiometricKeySetup(@NonNull FragmentActivity fragmentActivity) {
        return new Builder(fragmentActivity).setDummy().build();
    }


    /**
     * Construct prompt with all parameters.
     *
     * @param title Required dialog's title.
     * @param description Required dialog's description.
     * @param subtitle Optional dialog's subtitle.
     * @param isDummy Indicate that prompt contains dummy data.
     * @param fragment Parent fragment activity. If null, then parent fragment must be set.
     * @param fragmentActivity Parent fragment activity. If null, then fragment activity must be set.
     */
    private PowerAuthBiometricPrompt(
            @NonNull CharSequence title,
            @NonNull CharSequence description,
            @Nullable CharSequence subtitle,
            boolean isDummy,
            @Nullable Fragment fragment,
            @Nullable FragmentActivity fragmentActivity) {
        this.title = title;
        this.subtitle = subtitle;
        this.description = description;
        this.fragment = fragment;
        this.fragmentActivity = fragmentActivity;
        this.isDummy = isDummy;
    }

    /**
     * @return Dialog's title.
     */
    @NonNull
    public CharSequence getTitle() {
        return title;
    }

    /**
     * @return Optional dialog's subtitle.
     */
    @Nullable
    public CharSequence getSubtitle() {
        return subtitle;
    }

    /**
     * @return Dialog's description.
     */
    @NonNull
    public CharSequence getDescription() {
        return description;
    }

    /**
     * A builder that collects arguments for {@link PowerAuthBiometricPrompt}.
     */
    public static class Builder {
        private final Fragment fragment;
        private final FragmentActivity fragmentActivity;
        private CharSequence title;
        private CharSequence subtitle;
        private CharSequence description;
        private boolean isDummy;

        /**
         * Create builder with parent fragment activity.
         * @param fragmentActivity Parent {@link FragmentActivity}.
         */
        public Builder(@NonNull FragmentActivity fragmentActivity) {
            this.fragmentActivity = fragmentActivity;
            this.fragment = null;
        }

        /**
         * Create builder with parent fragment.
         * @param fragment Parent {@link Fragment}.
         */
        public Builder(@NonNull Fragment fragment) {
            this.fragmentActivity = null;
            this.fragment = fragment;
        }

        /**
         * Set title for the future biometric prompt. This parameter is required.
         * @param title Title for the future biometric prompt.
         * @return The same {@link Builder} object instance.
         */
        public Builder setTitle(@NonNull CharSequence title) {
            this.title = title;
            return this;
        }

        /**
         * Set subtitle for the future biometric prompt. This parameter is optional.
         * @param subtitle Subtitle for the future biometric prompt.
         * @return The same {@link Builder} object instance.
         */
        public Builder setSubtitle(@NonNull CharSequence subtitle) {
            this.subtitle = subtitle;
            return this;
        }

        /**
         * Set description for the future biometric prompt. This parameter is required.
         * @param description description for the future biometric prompt.
         * @return The same {@link Builder} object instance.
         */
        public Builder setDescription(@NonNull CharSequence description) {
            this.description = description;
            return this;
        }

        /**
         * Set prompt as dummy.
         * @return The same {@link Builder} object instance.
         */
        private Builder setDummy() {
            this.title = "dummy";
            this.description = "dummy";
            this.isDummy = true;
            return this;
        }

        /**
         * Build {@link PowerAuthBiometricPrompt} from the provided parameters.
         * @return Instance of {@link PowerAuthBiometricPrompt} class.
         * @throws IllegalArgumentException in case that required parameter is missing.
         */
        public PowerAuthBiometricPrompt build() {
            if (title == null) {
                throw new IllegalArgumentException("Biometric prompt's title cannot be null");
            }
            if (description == null) {
                throw new IllegalArgumentException("Biometric prompt's description cannot be null");
            }
            return new PowerAuthBiometricPrompt(title, subtitle, description, isDummy, fragment, fragmentActivity);
        }
    }

    // Internal properties

    /**
     * @return Parent fragment activity.
     */
    @Nullable FragmentActivity getFragmentActivity() {
        return fragmentActivity;
    }

    /**
     * @return Parent fragment.
     */
    @Nullable Fragment getFragment() {
        return fragment;
    }

    /**
     * @return Information whether this is dummy prompt.
     */
    boolean isDummy() {
        return isDummy;
    }
}
