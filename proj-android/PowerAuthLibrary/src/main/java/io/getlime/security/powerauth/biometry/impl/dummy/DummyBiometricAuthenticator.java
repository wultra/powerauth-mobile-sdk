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

package io.getlime.security.powerauth.biometry.impl.dummy;

import android.content.Context;
import androidx.annotation.NonNull;

import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.BiometryType;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.IBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.PrivateRequestData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

/**
 * The {@code DummyBiometricAuthenticator} class provides a dummy implementation of {@link IBiometricAuthenticator}
 * interface. The purpose of the class is to provide no keystore-related functions on devices which
 * doesn't have biometric device available or on devices with Android lesser than version 6.0.
 */
public class DummyBiometricAuthenticator implements IBiometricAuthenticator {

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public @BiometryType int getBiometryType(@NonNull Context context) {
        return BiometryType.NONE;
    }

    @Override
    public @BiometricStatus int canAuthenticate() {
        return BiometricStatus.NOT_SUPPORTED;
    }

    @NonNull
    @Override
    public IBiometricKeystore getBiometricKeystore() {
        return new DummyBiometricKeystore();
    }

    @NonNull
    @Override
    public ICancelable authenticate(@NonNull final Context context,
                                    @NonNull final PrivateRequestData requestData) throws PowerAuthErrorException {
        throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Biometric authentication is not supported on this device.");
    }
}
