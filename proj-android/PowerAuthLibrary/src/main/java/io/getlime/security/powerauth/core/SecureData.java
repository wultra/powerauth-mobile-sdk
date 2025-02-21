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

package io.getlime.security.powerauth.core;

import androidx.annotation.Nullable;
import androidx.annotation.NonNull;

import java.util.Arrays;

/**
 * The {@code SecureData} class encapsulates a byte array containing cryptographically sensitive data and ensures
 * that the data is securely erased from memory when the object is destroyed.
 */
public class SecureData {

    /**
     * Byte array with sensitive content.
     */
    @NonNull
    private final byte[] sensitiveData;

    /**
     * Construct object with provided array of bytes containing sensitive data.
     * @param sensitiveData Array of bytes with the sensitive data.
     */
    private SecureData(@NonNull byte[] sensitiveData) {
        this.sensitiveData = sensitiveData;
    }

    /**
     * Byte used to clear content of sensitive data stored in this class.
     */
    public static final byte CLEAR_BYTE_OURS = (byte) 0xCD;
    /**
     * Byte used to clear content of sensitive data stored in the external byte array.
     */
    public static final byte CLEAR_BYTE_OTHER = (byte) 0xDC;

    /**
     * Returns the byte array containing cryptographically sensitive data.  Note that you should not retain a reference
     * to this array. If you need to preserve the data outside this class, make a copy of the array instead.
     * Failing to do so may result in unexpected modifications when this instance is destroyed.
     *
     * @return A byte array containing the cryptographically sensitive data.
     */
    @NonNull
    public byte[] getSensitiveData() {
        return sensitiveData;
    }

    /**
     * @return Length of cryptographically sensitive data.
     */
    public int length() {
        return sensitiveData.length;
    }

    /**
     * @return New instance of {@link SecureData} with copied array of cryptographically sensitive data.
     */
    @NonNull
    public SecureData copy() {
        return new SecureData(Arrays.copyOf(sensitiveData, sensitiveData.length));
    }

    /**
     * Creates a new instance of {@link SecureData} with a copied array of cryptographically sensitive data.
     * If a {@code null} reference is provided, this method returns {@code null}.
     * <p>
     * This method is useful in situations, when the object owning the provided byte array still needs to use
     * the sensitive data and also ensures secure erase of the array.
     *
     * @param sensitiveData The byte array containing cryptographically sensitive data.
     * @return A new {@link SecureData} instance with a copied array of cryptographically sensitive data,
     *         or {@code null} if the input is {@code null}.
     */
    @Nullable
    public static SecureData copy(@Nullable byte[] sensitiveData) {
        if (sensitiveData != null) {
            return new SecureData(Arrays.copyOf(sensitiveData, sensitiveData.length));
        }
        return null;
    }

    /**
     * Creates a new instance of {@link SecureData} with a copied array of cryptographically sensitive data.
     * If a {@code null} reference is provided, this method returns {@code null}. Additionally, the provided
     * byte array is securely erased.
     * <p>
     * This method is useful when the object that owns the provided byte array does not securely erase its contents.
     * Ensure that the byte array is no longer needed by the owning object before calling this method.
     *
     * @param sensitiveData The byte array containing cryptographically sensitive data. This array will be erased.
     * @return A new {@link SecureData} instance with a copied array of cryptographically sensitive data,
     *         or {@code null} if the input is {@code null}.
     */
    @Nullable
    public static SecureData copyAndClearSource(@Nullable byte[] sensitiveData) {
        if (sensitiveData != null) {
            SecureData instance = new SecureData(Arrays.copyOf(sensitiveData, sensitiveData.length));
            Arrays.fill(sensitiveData, CLEAR_BYTE_OTHER);
            return instance;
        }
        return null;
    }

    /**
     * Creates a new instance of {@link SecureData} using the provided array of cryptographically sensitive data.
     * If a {@code null} reference is provided, this method returns {@code null}.
     * <p>
     * This method is intended for cases where no other object retains a reference to the provided byte array.
     * This typically occurs in functions that return a byte array after a cryptographic operation, such as
     * encryption or decryption.
     *
     * @param sensitiveData The byte array containing cryptographically sensitive data.
     * @return A new {@link SecureData} instance encapsulating the provided array,
     *         or {@code null} if the input is {@code null}.
     */
    @Nullable
    public static SecureData capture(@Nullable byte[] sensitiveData) {
        return sensitiveData != null ? new SecureData(sensitiveData) : null;
    }

    /**
     * Clear sensitive data immediately.
     */
    public synchronized void destroy() {
        Arrays.fill(sensitiveData, CLEAR_BYTE_OURS);
    }

    /**
     * Make sure that the content of sensitive data is always cleared.
     */
    @Override
    protected void finalize() {
        destroy();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof SecureData) {
            byte[] a = sensitiveData;
            byte[] b = ((SecureData) anObject).sensitiveData;
            if (a.length != b.length) {
                return false;
            }
            int differences = 0;
            for (int i = 0; i < a.length; i++) {
                differences |= a[i] ^ b[i];
            }
            return differences == 0;
        }
        return false;
    }
}
