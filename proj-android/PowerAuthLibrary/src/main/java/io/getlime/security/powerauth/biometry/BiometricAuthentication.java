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
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.UiThread;
import androidx.fragment.app.FragmentManager;
import android.util.Pair;

import java.util.concurrent.Executor;

import io.getlime.security.powerauth.biometry.impl.BiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.BiometricErrorDialogFragment;
import io.getlime.security.powerauth.biometry.impl.BiometricHelper;
import io.getlime.security.powerauth.biometry.impl.BiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.BiometricResultDispatcher;
import io.getlime.security.powerauth.biometry.impl.DefaultBiometricKeyEncryptorProvider;
import io.getlime.security.powerauth.biometry.impl.IBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.IBiometricKeyEncryptorProvider;
import io.getlime.security.powerauth.biometry.impl.PrivateRequestData;
import io.getlime.security.powerauth.biometry.impl.dummy.DummyBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.dummy.DummyBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.sdk.impl.DummyCancelable;
import io.getlime.security.powerauth.sdk.impl.MainThreadExecutor;
import io.getlime.security.powerauth.system.PowerAuthLog;

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
     * in this SDK. It's equivalent to call {@link #canAuthenticate(Context)} and compare result
     * to {@link BiometricStatus#OK}.
     *
     * @param context Android {@link Context} object
     * @return true if this authenticator supports a biometric authentication, otherwise false.
     */
    public static boolean isBiometricAuthenticationAvailable(@NonNull final Context context) {
        synchronized (SharedContext.class) {
            return getContext().getAuthenticator(context).canAuthenticate() == BiometricStatus.OK;
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
     * @param request {@link BiometricAuthenticationRequest} object with data for biometric authentication
     * @param callback {@link IBiometricAuthenticationCallback} callback to receive authentication result.
     * @return Returns {@link ICancelable} object that allows you to cancel that authentication request.
     */
    @UiThread
    public static @NonNull ICancelable authenticate(@NonNull final Context context,
                                                    @NonNull final BiometricAuthenticationRequest request,
                                                    @NonNull final IBiometricAuthenticationCallback callback) {
        synchronized (SharedContext.class) {
            // Check whether there's already pending authentication request.
            final SharedContext ctx = getContext();
            if (!ctx.startBiometricAuthentication()) {
                // There's already pending biometric authentication request.
                return reportSimultaneousRequest(callback);
            }

            // Acquire authenticator from the shared context
            final IBiometricAuthenticator device = ctx.getAuthenticator(context);
            // Prepare essential authentication request data
            final BiometricResultDispatcher dispatcher = new BiometricResultDispatcher(callback, MainThreadExecutor.getInstance(), new BiometricResultDispatcher.IResultCompletion() {
                @Override
                public void onCompletion() {
                    // Clear the pending request flag.
                    synchronized (SharedContext.class) {
                        ctx.finishPendingBiometricAuthentication();
                    }
                }

                @Override
                public void onBiometricKeyUnavailable() {
                    // Remove the default key, because the biometric key is no longer available.
                    device.getBiometricKeystore().removeBiometricKeyEncryptor();
                }
            });
            final IBiometricKeyEncryptorProvider biometricKeyEncryptorProvider = new DefaultBiometricKeyEncryptorProvider(request, getBiometricKeystore());
            final PrivateRequestData requestData = new PrivateRequestData(request, biometricKeyEncryptorProvider, dispatcher, ctx.getBiometricDialogResources(), ctx.isBiometricErrorDialogDisabled());

            // Validate request status
            @BiometricStatus int status = device.canAuthenticate();
            PowerAuthErrorException exception = null;
            if (status == BiometricStatus.OK) {
                try {
                    if (request.isForceGenerateNewKey() && !biometricKeyEncryptorProvider.isAuthenticationRequiredOnEncryption()) {
                        // Biometric authentication is not actually required, because we're generating (e.g encrypting) the key
                        // and the encryptor doesn't require authentication for such task.
                        return justEncryptBiometricKey(requestData, dispatcher);
                    } else {
                        // Authenticate with device
                        return device.authenticate(context, requestData);
                    }

                } catch (PowerAuthErrorException e) {
                    // Failed to authenticate. Show an error dialog and report that exception to the callback.
                    PowerAuthLog.e("BiometricAuthentication.authenticate() failed with exception: " + e.getMessage());
                    exception = e;
                    status = BiometricStatus.NOT_AVAILABLE;

                } catch (IllegalArgumentException e) {
                    // Failed to authenticate due to a wrong configuration.
                    PowerAuthLog.e("BiometricAuthentication.authenticate() failed with exception: " + e.getMessage());
                    exception = new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, e.getMessage(), e);
                    status = BiometricStatus.NOT_AVAILABLE;
                }
            }
            // Failed to use biometric authentication. At first, we should cleanup the possible stored
            // biometric key.
            device.getBiometricKeystore().removeBiometricKeyEncryptor();

            // Now show the error dialog, and report the exception later.
            if (exception == null) {
                exception = BiometricHelper.getExceptionForBiometricStatus(status);
            }
            if (requestData.isErrorDialogDisabled()) {
                // Error dialog is disabled, so report the error immediately. Use hint that error should be presented.
                dispatcher.dispatchError(BiometricErrorInfo.addToException(exception, true));
                return dispatcher.getCancelableTask();
            } else {
                // Error dialog is not disabled, so we can show it. Use hint that error was already presented.
                return showErrorDialog(status, BiometricErrorInfo.addToException(exception, false), context, requestData);
            }
        }
    }

    /**
     * This helper method only encrypts a raw key data with encryptor and dispatch result back to the
     * application. The encryptor should not require the biometric authentication on it's encrypt task.
     *
     * @param requestData Private request data.
     * @param dispatcher Biometric result dispatcher.
     * @return Result from {@link BiometricResultDispatcher#getCancelableTask()}.
     */
    private static @NonNull ICancelable justEncryptBiometricKey(
            @NonNull final PrivateRequestData requestData,
            @NonNull final BiometricResultDispatcher dispatcher) {
        // Prepare an encryption task
        final Runnable encryptTask = new Runnable() {
            @Override
            public void run() {
                try {
                    // Acquire encryptor and initialize the cipher
                    final IBiometricKeyEncryptor encryptor = requestData.getBiometricKeyEncryptorProvider().getBiometricKeyEncryptor();
                    final boolean initializationSuccess = encryptor.initializeCipher(true) != null;
                    // Encrypt the key
                    final BiometricKeyData keyData = initializationSuccess ? encryptor.encryptBiometricKey(requestData.getRequest().getRawKeyData()) : null;
                    if (keyData == null) {
                        throw new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Failed to encrypt biometric key.");
                    }
                    // Success, just dispatch the result back to the application
                    dispatcher.dispatchSuccess(keyData);
                } catch (PowerAuthErrorException e) {
                    // Failure, dispatch error back to the application
                    dispatcher.dispatchError(e);
                }
            }
        };
        // Execute the task on the background or on the current thread.
        final Executor executor = requestData.getRequest().getBackgroundTaskExecutor();
        if (executor != null) {
            executor.execute(encryptTask);
        } else {
            encryptTask.run();
        }
        return dispatcher.getCancelableTask();
    }

    /**
     * Show dialog fragment with the error message in case that the biometric authentication fails at the authentication initialization phase.
     *
     * @param status {@link BiometricStatus} that caused the failure.
     * @param exception {@link PowerAuthErrorException} that will be reported to the callback.
     * @param context Android {@link Context} object
     * @param requestData Private request data.
     * @return Returns {@link ICancelable} object that allows you to cancel that authentication request.
     */
    private static @NonNull ICancelable showErrorDialog(
            @BiometricStatus int status,
            @NonNull final PowerAuthErrorException exception,
            @NonNull final Context context,
            @NonNull final PrivateRequestData requestData) {

        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        final CancelableTask cancelableTask = dispatcher.getCancelableTask();
        final FragmentManager fragmentManager = requestData.getFragmentManager();

        final BiometricDialogResources resources = requestData.getResources();
        final Pair<Integer, Integer> titleDescription = BiometricHelper.getErrorDialogStringsForBiometricStatus(status, resources.strings);

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(titleDescription.first)
                .setMessage(titleDescription.second)
                .setCloseButton(resources.strings.ok)
                .setIcon(resources.drawables.errorIcon)
                .setOnCloseListener(new BiometricErrorDialogFragment.OnCloseListener() {
                    @Override
                    public void onClose() {
                        dispatcher.dispatchError(exception);
                    }
                })
                .build();
        // Handle cancel from the application
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
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
     * Report cancel to provided callback in case that this is the simultaneous biometric authentication request.
     * @param callback Callback to report the cancel.
     * @return Dummy {@link ICancelable} object that does nothing.
     */
    private static ICancelable reportSimultaneousRequest(@NonNull final IBiometricAuthenticationCallback callback) {
        PowerAuthLog.e("Cannot execute more than one biometric authentication request at the same time. This request is going to be canceled.");
        // Report cancel to the main thread.
        MainThreadExecutor.getInstance().dispatchCallback(new Runnable() {
            @Override
            public void run() {
                // Report cancel.
                callback.onBiometricDialogCancelled(false);
            }
        });
        // Return dummy cancelable object.
        return new DummyCancelable();
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
    public static @NonNull BiometricDialogResources getBiometricDialogResources() {
        synchronized (SharedContext.class) {
            return getContext().getBiometricDialogResources();
        }
    }

    /**
     * Disable or enable error dialog provided by PowerAuth mobile SDK and displayed after failed biometric authentication.
     * <p>
     * If set to {@code true}, then the custom error dialog provided by the PowerAuth mobile SDK will never
     * be displayed in the case of authentication failure. The mobile application should handle all possible error
     * states using its own UI elements. The default value for this property is {@code false}, and the PowerAuth mobile
     * SDK may display its own error dialog.
     *
     * @param disabled If {@code true}, then the PowerAuth mobile SDK will never display its own error dialog.
     */
    public static void setBiometricErrorDialogDisabled(boolean disabled) {
        synchronized (SharedContext.class) {
            getContext().setBiometricErrorDialogDisabled(disabled);
        }
    }

    /**
     * Return information whether error dialog provided by PowerAuth mobile SDK is disabled or enabled.
     * @return {@code true} in case that the PowerAuth mobile SDK will never display its own error dialog, {@code false} otherwise.
     */
    public static boolean isBiometricErrorDialogDisabled() {
        synchronized (SharedContext.class) {
            return getContext().isBiometricErrorDialogDisabled();
        }
    }

    /**
     * Return type of biometry supported on the system.
     *
     * @param context Android context object
     * @return {@link BiometryType} representing supported biometry on the system.
     */
    public static @BiometryType int getBiometryType(@NonNull Context context) {
        synchronized (SharedContext.class) {
            return getContext().getBiometryType(context);
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
         * Contains {@code true} in case that application want's to deal with authentication errors in its own UI.
         * The default value is {@code false};
         */
        private boolean isBiometricErrorDialogDisabled = false;

        /**
         * Contains {@code true} in case that there's already pending biometric authentication.
         */
        private boolean isPendingBiometricAuthentication = false;

        /**
         * Private {@code SharedContext} constructor.
         */
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
         * @param disabled if true, then error dialog provided by PowerAuth mobile SDK will be disabled.
         */
        void setBiometricErrorDialogDisabled(boolean disabled) {
            isBiometricErrorDialogDisabled = disabled;
        }

        /**
         * @return true when error dialog provided by PowerAuth mobile SDK is be disabled.
         */
        boolean isBiometricErrorDialogDisabled() {
            return isBiometricErrorDialogDisabled;
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
            // If Android 6.0 "Marshmallow" and newer, then try to build authenticator using BiometricPrompt from support lib.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                final IBiometricAuthenticator newAuthenticator = BiometricAuthenticator.createAuthenticator(context, getBiometricKeystore());
                if (newAuthenticator != null) {
                    return newAuthenticator;
                }
            }
            // Otherwise return dummy authenticator, which provides no biometric functions.
            // In this case, we can cache the authenticator.
            authenticator = new DummyBiometricAuthenticator();
            return authenticator;
        }

        /**
         * Check whether there's a pending biometric authentication request. If no, then start
         * a new one.
         *
         * @return {@code false} if there's already pending biometric authentication request.
         */
        boolean startBiometricAuthentication() {
            if (isPendingBiometricAuthentication) {
                return false;
            }
            isPendingBiometricAuthentication = true;
            return true;
        }

        /**
         * Finish previously started biometric authentication request.
         */
        void finishPendingBiometricAuthentication() {
            isPendingBiometricAuthentication = false;
        }

        /**
         * Flag that indicates that value of {@link #biometryType} is already evaluated.
         */
        private boolean isBiometryTypeEvaluated = false;

        /**
         * Evaluated type of biometry supported on the device.
         */
        private @BiometryType int biometryType = BiometryType.NONE;

        /**
         * Return type of biometry supported on the system.
         *
         * @param context Android context object
         * @return {@link BiometryType} representing supported biometry on the system.
         */
        @BiometryType int getBiometryType(@NonNull Context context) {
            if (!isBiometryTypeEvaluated) {
                final IBiometricAuthenticator authenticator = getAuthenticator(context);
                biometryType = authenticator.getBiometryType(context);
                if (biometryType == BiometryType.NONE) {
                    // If reported type is NONE, then try to test whether we can authenticate. If yes, then this is
                    // a broken device or Android SDK added new type of biometric sensor. In both situations, we
                    // should report "GENERIC" type.
                    final int state = authenticator.canAuthenticate();
                    if (state == BiometricStatus.OK || state == BiometricStatus.NOT_ENROLLED) {
                        PowerAuthLog.w("BiometricAuthentication: Fallback to BiometryType.GENERIC");
                        biometryType = BiometryType.GENERIC;
                    }
                }
                isBiometryTypeEvaluated = true;
            }
            return biometryType;
        }
    }

    /**
     * @return Object with shared data.
     */
    private static @NonNull SharedContext getContext() {
        return SharedContext.INSTANCE;
    }
}
