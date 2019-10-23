/*
 * Copyright 2019 Wultra s.r.o.
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

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.StringRes;
import android.support.annotation.UiThread;
import android.support.v4.app.FragmentManager;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.impl.BiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.BiometricErrorDialogFragment;
import io.getlime.security.powerauth.biometry.impl.BiometricHelper;
import io.getlime.security.powerauth.biometry.impl.BiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.BiometricResultDispatcher;
import io.getlime.security.powerauth.biometry.impl.IBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.PrivateRequestData;
import io.getlime.security.powerauth.biometry.impl.dummy.DummyBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.dummy.DummyBiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.legacy.FingerprintAuthenticator;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.sdk.impl.DefaultCallbackDispatcher;

/**
 * The {@code BiometricAuthentication} class is a high level interface that provides interfaces related
 * to the biometric authentication. The class hides all technical details, so it can be safely
 * used also on the systems that doesn't provide biometric interfaces, or if the system has no
 * biometric sensor available.
 *
 * The class is internally used in the PowerAuth Mobile SDK, but can be utilized also by the
 * application developers.
 */
public class BiometricAuthentication {

  /**
     * Returns object representing a Keystore used to store biometry related key. If the biometric
     * authentication is not available on the authenticator, then returns a dummy implementation where
     * all interface methods fails, or does not provide the required information.
     *
     * @return Object implementing {@link IBiometricKeystore} interface.
     */
    public static @NonNull IBiometricKeystore getBiometricKeystore() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return new BiometricKeystore();
        }
        return new DummyBiometricKeystore();
    }


    /**
     * Check whether biometric authentication is available on this authenticator and can be used
     * in this SDK.
     *
     * @param context Android {@link Context} object
     * @return true if this authenticator supports a biometric authentication, otherwise false.
     */
    public static boolean isBiometricAuthenticationAvailable(@NonNull final Context context) {
        synchronized (SharedContext.class) {
            return getContext().getAuthenticator(context).isAvailable();
        }
    }


    /**
     * Check whether biometric authentication is available on this authenticator and biometric data
     * are enrolled on the system.
     *
     * @param context Android {@link Context} object
     * @return Constant integer from {@link BiometricStatus} interface, representing status of
     *         biometry on the authenticator.
     */
    public static @BiometricStatus int canAuthenticate(@NonNull final Context context) {
        synchronized (SharedContext.class) {
            return getContext().getAuthenticator(context).canAuthenticate();
        }
    }

    /**
     * Performs biometric authentication.
     *
     * @param context Android {@link Context} object
     * @param fragmentManager Android {@link FragmentManager} object
     * @param request {@link BiometricAuthenticationRequest} object with data for biometric authentication
     * @param callback {@link IBiometricAuthenticationCallback} callback to receive authentication result.
     * @return Returns {@link ICancelable} object that allows you to cancel that authentication request.
     */
    @UiThread
    public static @NonNull ICancelable authenticate(@NonNull final Context context,
                                                    @NonNull final FragmentManager fragmentManager,
                                                    @NonNull final BiometricAuthenticationRequest request,
                                                    @NonNull final IBiometricAuthenticationCallback callback) {
        synchronized (SharedContext.class) {
            // Acquire authenticator from the context
            final SharedContext ctx = getContext();
            final IBiometricAuthenticator device = ctx.getAuthenticator(context);
            // Prepare essential authentication request data
            final BiometricResultDispatcher dispatcher = new BiometricResultDispatcher(callback, new DefaultCallbackDispatcher());
            final PrivateRequestData requestData = new PrivateRequestData(request, dispatcher, ctx.getBiometricDialogResources());

            // Validate request status
            @BiometricStatus int status = device.canAuthenticate();
            PowerAuthErrorException exception = null;
            if (status == BiometricStatus.OK) {
                try {
                    // Prepare secret key for authentication
                    requestData.setSecretKey(prepareSecretKey(device.getBiometricKeystore(), request.isForceGenerateNewKey()));
                    // Authenticate
                    return device.authenticate(context, fragmentManager, requestData);

                } catch (PowerAuthErrorException e) {
                    // Failed to authenticate. Show an error dialog and report that exception to the callback.
                    exception = e;
                    status = BiometricStatus.NOT_AVAILABLE;
                }
            }
            // Failed to use biometric authentication. At first, we should cleanup the possible stored
            // biometric key.
            device.getBiometricKeystore().removeDefaultKey();

            // Now show the error dialog, and report the exception later.
            if (exception == null) {
                exception = BiometricHelper.getExceptionForBiometricStatus(status);
            }
            return showErrorDialog(status, exception, context, fragmentManager, requestData);
        }
    }

    /**
     * Prepare secret key, stored (or restored) managed by {@link IBiometricKeystore} object.
     * @param keystore Keystore object managing the requested key.
     * @param createNewKey If {@code true}, then the new key is created in the keystore.
     * @return {@link SecretKey} acquired from the keystore.
     * @throws PowerAuthErrorException In case that cannot create or restore the key.
     */
    private static @NonNull SecretKey prepareSecretKey(IBiometricKeystore keystore, boolean createNewKey) throws PowerAuthErrorException {
        final SecretKey key;
        if (createNewKey) {
            key = keystore.generateDefaultKey();
            if (key == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Keystore failed to generate a new biometric key.");
            }
        } else {
            key = keystore.getDefaultKey();
            if (key == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Cannot get biometric key from the keystore.");
            }
        }
        return key;
    }

    /**
     * Show dialog fragment with the error message in case that the biometric authentication fails at the authentication initialization phase.
     *
     * @param status {@link BiometricStatus} that caused the failure.
     * @param exception {@link PowerAuthErrorException} that will be reported to the callback.
     * @param context Android {@link Context} object
     * @param fragmentManager Fragment manager that manages created alert
     * @param requestData Private request data.
     * @return Returns {@link ICancelable} object that allows you to cancel that authentication request.
     */
    private static @NonNull ICancelable showErrorDialog(
            @BiometricStatus int status,
            @NonNull final PowerAuthErrorException exception,
            @NonNull final Context context,
            @NonNull final FragmentManager fragmentManager,
            @NonNull final PrivateRequestData requestData) {

        final CancelableTask cancelableTask = requestData.getDispatcher().getCancelableTask();

        final BiometricDialogResources resources = requestData.getResources();
        final @StringRes int errorTitle;
        final @StringRes int errorDescription;
        if (status == BiometricStatus.NOT_ENROLLED) {
            // User must enroll at least one fingerprint
            errorTitle       = resources.strings.errorEnrollFingerprintTitle;
            errorDescription = resources.strings.errorEnrollFingerprintDescription;
        } else if (status == BiometricStatus.NOT_SUPPORTED) {
            // Fingerprint scanner is not supported on the authenticator
            errorTitle       = resources.strings.errorNoFingerprintScannerTitle;
            errorDescription = resources.strings.errorNoFingerprintScannerDescription;
        } else if (status == BiometricStatus.NOT_AVAILABLE) {
            // Fingerprint scanner is disabled in the system, or permission was not granted.
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        } else {
            // Fallback...
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        }

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(errorTitle)
                .setMessage(errorDescription)
                .setCloseButton(resources.strings.ok, resources.colors.closeButtonText)
                .setIcon(resources.drawables.errorIcon)
                .setOnCloseListener(new BiometricErrorDialogFragment.OnCloseListener() {
                    @Override
                    public void onClose() {
                        requestData.getDispatcher().dispatchError(exception);
                    }
                })
                .build();
        // Handle cancel from the application
        requestData.getDispatcher().setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                dialogFragment.dismiss();
            }
        });

        // Show fragment
        dialogFragment.show(fragmentManager, BiometricErrorDialogFragment.FRAGMENT_DEFAULT_TAG);

        return cancelableTask;
    }


    /**
     * Sets shared {@link BiometricDialogResources} object to this class. You can use this method
     * to override a default resources provided by this SDK.
     *
     * @param resources New biometric dialog resources to be set.
     */
    public static void setBiometricDialogResources(@NonNull BiometricDialogResources resources) {
        synchronized (SharedContext.class) {
            getContext().setBiometricDialogResources(resources);
        }
    }

    /**
     * @return Shared instance of {@link BiometricDialogResources} object.
     */
    public @NonNull BiometricDialogResources getBiometricDialogResources() {
        synchronized (SharedContext.class) {
            return getContext().getBiometricDialogResources();
        }
    }

    /**
     * Set new {@code BiometricPrompt} based authentication disabled for this device and force to use
     * the legacy {@code FingerprintManager} authenticator. This is useful for situations when device's
     * manufacturer provides a faulty implementation of {@code BiometricPrompt} and therefore
     * PowerAuth SDK cannot use it for biometric authentication tasks.
     *
     * @param disabled Set {@code true} to disable new {@code BiometricPrompt} based authentication method.
     */
    public static void setBiometricPromptAuthenticationDisabled(boolean disabled) {
        synchronized (SharedContext.class) {
            getContext().setBiometricPromptAuthenticationDisabled(disabled);
        }
    }

    /**
     * @return {@code true} when {@code BiometricPrompt} based authentication is disabled for this device.
     */
    public static boolean isBiometricPromptAuthenticationDisabled() {
        synchronized (SharedContext.class) {
            return getContext().isBiometricPromptAuthenticationDisabled();
        }
    }

    /**
     * The {@code SharedContext} nested class contains shared data, required for the biometric tasks.
     */
    private static class SharedContext {

        /**
         * Shared instance of this class.
         */
        private static final SharedContext INSTANCE = new SharedContext();

        /**
         * Contains shared {@link BiometricDialogResources} object.
         */
        private @NonNull BiometricDialogResources biometricDialogResources;

        /**
         * Contains {@link IBiometricAuthenticator} in case that keeping a reference to a permanent authenticator
         * may be tolerable. This is for example in cases that biometric functions are not available
         * on the authenticator.
         */
        private @Nullable IBiometricAuthenticator authenticator;

        /**
         * Contains {@code true} in case that legacy biometric authentication must be used on devices
         * supporting the new {@code BiometricPrompt}.
         */
        private boolean isBiometricPromptAuthenticationDisabled = false;

        private SharedContext() {
            biometricDialogResources = new BiometricDialogResources.Builder().build();
            authenticator = null;
        }

        /**
         * @param resources Sets new {@link BiometricDialogResources} object with resources for
         *                  fingerprint dialog resources.
         */
        void setBiometricDialogResources(@NonNull BiometricDialogResources resources) {
            biometricDialogResources = resources;
        }

        /**
         * @return {@link BiometricDialogResources} shared object with resources for fingerprint dialog.
         */
        @NonNull BiometricDialogResources getBiometricDialogResources() {
            return biometricDialogResources;
        }

        /**
         * @return {@code true} if new {@code BiometricPrompt} based authentication is disabled.
         */
        boolean isBiometricPromptAuthenticationDisabled() {
            return isBiometricPromptAuthenticationDisabled;
        }

        /**
         * Set new {@code BiometricPrompt} based authentication disabled.
         * @param disabled Set {@code true} to disable {@code BiometricPrompt} based authentication.
         */
        void setBiometricPromptAuthenticationDisabled(boolean disabled) {
            isBiometricPromptAuthenticationDisabled = disabled;
        }

        /**
         * Returns object implementing {@link IBiometricAuthenticator} interface. The returned implementation
         * depends on the version of Android system and on the authenticator's capabilities. If current system
         * doesn't support biometric related APIs, or if the authenticator itself has no biometric sensor
         * available, then returns a dummy implementation that reject all requested operations.
         *
         * @param context Android {@link Context} object
         * @return Object implementing {@link IBiometricAuthenticator} interface.
         */
        @NonNull
        IBiometricAuthenticator getAuthenticator(@NonNull final Context context) {
            // Check if authenticator has been already created
            if (authenticator != null) {
                return authenticator;
            }
            // If Android 9.0 "Pie" and newer, then try to build authenticator supporting BiometricPrompt.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !isBiometricPromptAuthenticationDisabled) {
                final IBiometricAuthenticator newAuthenticator = BiometricAuthenticator.createAuthenticator(context, getBiometricKeystore());
                if (newAuthenticator != null) {
                    return newAuthenticator;
                }
            }
            // If Android 6.0 "Marshmallow" and newer, then try to build authenticator based on FingerprintManager.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                final IBiometricAuthenticator newAuthenticator = FingerprintAuthenticator.createAuthenticator(context, getBiometricKeystore());
                if (newAuthenticator != null) {
                    return newAuthenticator;
                }
            }
            // Otherwise return dummy authenticator, which provides no biometric functions.
            // In this case, we can cache the authenticator.
            authenticator = new DummyBiometricAuthenticator();
            return authenticator;
        }
    }

    /**
     * @return Object with shared data.
     */
    private static @NonNull SharedContext getContext() {
        return SharedContext.INSTANCE;
    }
}
