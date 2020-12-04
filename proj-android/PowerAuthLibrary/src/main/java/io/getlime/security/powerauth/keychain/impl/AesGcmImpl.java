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

package io.getlime.security.powerauth.keychain.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code AesGcmImpl} class implements AES-GCM encryption and decryption.
 */
public class AesGcmImpl {

    /**
     * AES-GCM cipher identifier.
     */
    public static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    /**
     * Size of IV for AES-GCM cipher.
     */
    public static final int IV_SIZE_IN_BYTES = 12;
    /**
     * Size of TAG for AES-GCM cipher.
     */
    public static final int TAG_SIZE_IN_BYTES = 16;

    /**
     * Encrypt provided data with secret key.
     *
     * @param plaintext Data to be encrypted.
     * @param key Encryption key
     * @param identifier String identifier as a source for AAD.
     * @return Encrypted data or {@code null} in case of failure.
     */
    @Nullable
    public static byte[] encrypt(@NonNull byte[] plaintext, @NonNull SecretKey key, @NonNull String identifier) {
        try {
            if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
                PA2Log.e("AesGcmImpl: " + identifier + ": Plaintext is too long.");
                return null;
            }
            final byte[] ciphertext = new byte[IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES];
            final byte[] aad = identifier.getBytes(Charset.defaultCharset());
            final Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.updateAAD(aad);
            cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, IV_SIZE_IN_BYTES);
            // Copy generated IV back to the final ciphertext.
            System.arraycopy(cipher.getIV(), 0, ciphertext, 0, IV_SIZE_IN_BYTES);
            return ciphertext;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | ShortBufferException e) {
            PA2Log.e("AesGcmImpl: " + identifier + ": Failed to encrypt keychain value. Exception: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt previously encrypted data with secret key.
     *
     * @param ciphertext Data to be decrypted.
     * @param key Decryption key.
     * @param identifier String identifier as a source for AAD.
     * @return Decrypted data or {@code null} in case of failure.
     */
    @Nullable
    public static byte[] decrypt(@NonNull byte[] ciphertext, @NonNull SecretKey key, @NonNull String identifier) {
        try {
            if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
                PA2Log.e("AesGcmImpl: " + identifier + ": Ciphertext is too short.");
                return null;
            }
            final byte[] aad = identifier.getBytes(Charset.defaultCharset());
            final GCMParameterSpec spec = new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, ciphertext, 0, IV_SIZE_IN_BYTES);
            final Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext, IV_SIZE_IN_BYTES, ciphertext.length - IV_SIZE_IN_BYTES);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("AesGcmImpl: " + identifier + ": Failed to decrypt keychain value. Exception: " + e.getMessage());
            return null;
        }
    }
}
