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

package io.getlime.security.powerauth.biometry.impl;

import android.os.SystemClock;
import androidx.annotation.NonNull;

import androidx.fragment.app.FragmentManager;
import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;

/**
 * The {@code PrivateRequestData} class contains various temporary data required for the biometric
 * authentication request processing. The class is used internally by the SDK.
 */
public class PrivateRequestData {

    private final @NonNull BiometricAuthenticationRequest request;
    private final @NonNull BiometricResultDispatcher dispatcher;
    private final @NonNull BiometricDialogResources resources;
    private final @NonNull IBiometricKeyEncryptorProvider biometricKeyEncryptorProvider;
    private final boolean errorDialogDisabled;
    private final long creationTime;

    /**
     * Construct private request data object.
     *
     * @param request Original, application provided request object.
     * @param biometricKeyEncryptorProvider Object that provide {@link IBiometricKeyEncryptor} on demand.
     * @param dispatcher Dispatcher that holds completion callback and callback dispatcher.
     * @param resources Resources required for the legacy implementation.
     * @param errorDialogDisabled If true then error dialog should not be displayed.
     */
    public PrivateRequestData(@NonNull BiometricAuthenticationRequest request,
                              @NonNull IBiometricKeyEncryptorProvider biometricKeyEncryptorProvider,
                              @NonNull BiometricResultDispatcher dispatcher,
                              @NonNull BiometricDialogResources resources,
                              boolean errorDialogDisabled) {
        this.request = request;
        this.biometricKeyEncryptorProvider = biometricKeyEncryptorProvider;
        this.dispatcher = dispatcher;
        this.resources = resources;
        this.creationTime = SystemClock.elapsedRealtime();
        this.errorDialogDisabled = errorDialogDisabled;
    }

    /**
     * @return {@link BiometricAuthenticationRequest} associated with this private data object.
     */
    public @NonNull BiometricAuthenticationRequest getRequest() {
        return request;
    }

    /**
     * @return {@link IBiometricKeyEncryptorProvider} that can provide {@link IBiometricKeyEncryptor} on demand.
     */
    public @NonNull IBiometricKeyEncryptorProvider getBiometricKeyEncryptorProvider() {
        return biometricKeyEncryptorProvider;
    }

    /**
     * @return {@link BiometricResultDispatcher} associated with this private data object.
     */
    public @NonNull BiometricResultDispatcher getDispatcher() {
        return dispatcher;
    }

    /**
     * @return {@link BiometricDialogResources} object with resources for biometric dialog.
     */
    public @NonNull BiometricDialogResources getResources() {
        return resources;
    }

    /**
     * @return Elapsed time in milliseconds since the request was created.
     */
    public long getElapsedTime() {
        return SystemClock.elapsedRealtime() - creationTime;
    }

    /**
     * @return {@code true} if error dialog after failed authentication should not be displayed.
     */
    public boolean isErrorDialogDisabled() {
        return errorDialogDisabled;
    }

    /**
     * This helper method return {@link FragmentManager} from Fragment or FragmentActivity
     * provided in {@link BiometricAuthenticationRequest}. The method throws {@code IllegalStateException}
     * in case that Fragment is not attached yet, or the request is mis-configured.
     *
     * @return {@link FragmentManager} object acquired from request's Fragment or FragmentActivity.
     */
    public @NonNull FragmentManager getFragmentManager() {
        if (request.getFragment() != null) {
            return request.getFragment().getChildFragmentManager();
        } else if (request.getFragmentActivity() != null) {
            return request.getFragmentActivity().getSupportFragmentManager();
        }
        throw new IllegalStateException("Fragment or FragmentActivity is missing.");
    }
}
