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

package io.getlime.security.powerauth.keychain.fingerprint;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v4.app.DialogFragment;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author Petr Dvorak
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintAuthenticationHandler extends FingerprintManager.AuthenticationCallback {

    private FingerprintCallback mCallback;
    private final FingerprintManager mFingerprintManager;
    private CancellationSignal mCancellationSignal;
    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintKeystore mKeyStore;
    private Cipher mCipher;
    private boolean mForceGenerateNewKey;

    /**
     * Builder for a 'FingerprintAuthenticationHandler' class.
     */
    public static class FingerprintHelperBuilder {

        private final FingerprintManager mFingerPrintManager;
        private FingerprintCallback mCallback;
        private boolean mForceGenerateNewKey;

        public FingerprintHelperBuilder(Context context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mFingerPrintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
            } else {
                mFingerPrintManager = null;
            }
        }

        public FingerprintHelperBuilder forceGenerateNewKey(boolean forceGenerateNewKey) {
            mForceGenerateNewKey = forceGenerateNewKey;
            return this;
        }

        public FingerprintHelperBuilder callback(FingerprintCallback callback) {
            mCallback = callback;
            return this;
        }

        public FingerprintAuthenticationHandler build() {
            return new FingerprintAuthenticationHandler(mFingerPrintManager, mCallback, mForceGenerateNewKey);
        }
    }

    private FingerprintAuthenticationHandler(FingerprintManager fingerprintManager, FingerprintCallback callback, boolean forceGenerateNewKey) {
        mFingerprintManager = fingerprintManager;
        mCallback = callback;
        mForceGenerateNewKey = forceGenerateNewKey;
        if (!initKeyStore()) {
            mCallback.onAuthenticationFailed();
        }
    }

    /**
     * Release fingerprint callback to avoid memory leak.
     * The callback is a {@link DialogFragment} which holds reference to the activity.
     *
     * It's necessary to break the reference chain because
     * {@link FingerprintManager} doesn't release reference to {@link FingerprintAuthenticationHandler}
     * and we leak activities when using {@link FingerprintManager}.
     */
    public void releaseFingerprintCallback() {
        mCallback = null;
    }

    //<editor-fold desc="Methods related to fingerprint authentication availability checks">

    /**
     * Check if fingerprint authentication is available
     *
     * @return true when fingerprints login available - hw available and user enrolled fingerprints, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public boolean isFingerprintAuthAvailable() throws SecurityException {
        return mFingerprintManager != null && mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints();
    }

    /**
     * Check if the device has a fingerprint scanner hardware.
     *
     * @return true when device has compatible fingerprint scanner hardware, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public boolean hasFingerprintHardware() throws SecurityException {
        return mFingerprintManager != null && mFingerprintManager.isHardwareDetected();
    }

    /**
     * Check if user has some fingerprints enrolled in the device.
     *
     * @return true when use has enrolled fingerprints, otherwise false
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public boolean hasEnrolledFingerprints() throws SecurityException {
        return mFingerprintManager != null && mFingerprintManager.hasEnrolledFingerprints();
    }

    /**
     * Start listening for fingerprint authentication.
     * @throws SecurityException In case user didn't grant permissions to use Fingerprint
     */
    public void startListening() throws SecurityException {
        if (isFingerprintAuthAvailable()) {
            mCancellationSignal = new CancellationSignal();
            mFingerprintManager.authenticate(mCryptoObject, mCancellationSignal, 0, this, null);
        }
    }

    /**
     * Stop listening for fingerprint authentication.
     */
    public void stopListening() {
        if (mCancellationSignal != null) {
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }

    //</editor-fold>

    /**
     * Try to initialize a Keystore instance.
     *
     * If this method call fails, it indicates serious issue with a Keystore system on current Android version.
     * @return Returns 'true' in case Keystore was initialized, 'false' otherwise.
     */
    private boolean initKeyStore() {
        mKeyStore = new FingerprintKeystore();
        return mKeyStore.isKeystoreReady();
    }

    /**
     * Initialize a cipher object for AES/CBC/PKCS7 algorithm.
     * @return True in case cipher was correctly initialized, false otherwise
     */
    private boolean initCipher() {
        try {
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            SecretKey key = mKeyStore.getDefaultKey();
            if (key != null) {
                final byte[] zero_iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                AlgorithmParameterSpec algorithmSpec = new IvParameterSpec(zero_iv);
                mCipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
                return true;
            } else {
                return false;
            }
        } catch (NoSuchPaddingException e) {
            return false;
        } catch (InvalidAlgorithmParameterException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
            return false;
        } catch (InvalidKeyException e) {
            return false;
        }
    }

    /**
     * Helper method to remove the default key from the KeyStore.
     * @return True if key is removed without error, false otherwise (in case Keystore is not initialized correctly).
     */
    public boolean removeKey() {
        return mKeyStore.removeDefaultKey();
    }

    /**
     * Initialize a crypto object associated with fingerprint authentication.
     * @return {@link FingerprintStage} enumeration
     */
    public FingerprintStage initCrypto() {

        if (!hasFingerprintHardware()) {
            return FingerprintStage.INFO_FINGERPRINT_NOT_AVAILABLE;
        }

        if (!hasEnrolledFingerprints()) {
            return FingerprintStage.INFO_ENROLL_NEW_FINGERPRINT;
        }

        if (mForceGenerateNewKey) {
            if (!mKeyStore.generateDefaultKey()) {
                return FingerprintStage.INFO_FINGERPRINT_NOT_AVAILABLE;
            }
        } else {
            if (!mKeyStore.containsDefaultKey()) {
                return FingerprintStage.INFO_FINGERPRINT_NOT_AVAILABLE;
            }
        }

        if (initCipher()) {
            mCryptoObject = new FingerprintManager.CryptoObject(mCipher);
            return FingerprintStage.USE_FINGERPRINT;
        } else {
            return FingerprintStage.INFO_FINGERPRINT_INVALIDATED;
        }
    }

    /**
     * Contains cached encrypted key. The value is calculated only for once.
     */
    private byte[] alreadyEncryptedKey;

    /**
     * Contains true if {@link #alreadyEncryptedKey} has been already constructed.
     * The purpose of this flag is to prevent duplicate calls to {@code mCipher.doFinal()}.
     */
    private boolean hasAlreadyEncryptedKey;

    /**
     * Encrypt provided data using internal cipher object.
     * @param biometryKey Data to be encrypted.
     * @return Encrypted data, or null in case exception occurs.
     */
    public byte[] encryptedKey(byte[] biometryKey) {
        try {
            synchronized (this) {
                if (!hasAlreadyEncryptedKey) {
                    hasAlreadyEncryptedKey = true;
                    alreadyEncryptedKey = mCipher.doFinal(biometryKey);
                }
                return alreadyEncryptedKey;
            }
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);

        if (mCallback != null) {
            mCallback.onAuthenticationHelp(helpString);
        }
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);

        if (mCallback != null) {
            mCallback.onAuthenticated();
        }
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);

        if (mCallback != null) {
            mCallback.onAuthenticationError(errString);
        }
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();

        if (mCallback != null) {
            mCallback.onAuthenticationFailed();
        }
    }

}
