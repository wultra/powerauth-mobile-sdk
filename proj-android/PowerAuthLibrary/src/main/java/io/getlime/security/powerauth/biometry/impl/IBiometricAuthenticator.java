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

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.UiThread;
import androidx.fragment.app.FragmentManager;

import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.BiometryType;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

/**
 * The {@code IBiometricAuthenticator} is an interface providing biometric authentication.
 * The interface provides functions that allows you determine whether biometric authentication can
 * be used and also provides the authentication method itself.
 */
public interface IBiometricAuthenticator {

    /**
     * Evaluate whether the biometric authentication is supported on the system.
     *
     * @return {@code true} if current device and operating system supports biometric authentication, otherwise {@code false}.
     */
    boolean isAvailable();

    /**
     * Return type of biometry supported on the system.
     *
     * @param context Android context object
     * @return {@link BiometryType} representing supported biometry on the system.
     */
    @BiometryType int getBiometryType(@NonNull Context context);

    /**
     * Evaluate whether the biometric authentication is available at the time of the call.
     *
     * @return Current {@link BiometricStatus} that determines whether you can call authenticate method.
     */
    @BiometricStatus int canAuthenticate();

    /**
     * @return {@link IBiometricKeystore} object managing lifetime of biometry related key.
     */
    @NonNull IBiometricKeystore getBiometricKeystore();

    /**
     * Perform biometric authentication defined by the {@link PrivateRequestData}.
     *
     * @param context Android {@link Context} object
     * @param privateRequestData Private request data.
     * @return {@link ICancelable} object that allows you to cancel that authentication request.
     * @throws PowerAuthErrorException In case that cannot perform the biometric authentication.
     */
    @UiThread
    @NonNull
    ICancelable authenticate(
            @NonNull final Context context,
            @NonNull final PrivateRequestData privateRequestData) throws PowerAuthErrorException;

}
