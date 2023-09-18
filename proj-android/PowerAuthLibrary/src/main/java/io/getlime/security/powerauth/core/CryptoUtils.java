/*
 * Copyright 2018 Wultra s.r.o.
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Arrays;

/**
 * The CryptoUtils class provides a several general cryptographic primitives
 * required in our other open source libraries.
 */
public class CryptoUtils {

    static {
        System.loadLibrary("PowerAuth2Module");
    }

    /**
     * Generate new EcKeyPair for Elliptic Curve cryptography routines. NIST P-256 curve is used under the hood.
     * @return New key-pair or null in case of failure.
     */
    public static native EcKeyPair ecGenerateKeyPair();

    /**
     * Validates ECDSA signature for given data and EC public key.
     *
     * @param data signed data
     * @param signature signature calculated for data
     * @param publicKey EC public key
     * @return true if signature is valid
     */
    public static native boolean ecdsaValidateSignature(byte[] data, byte[] signature, EcPublicKey publicKey);

    /**
     * Create ECDSA signature for given data and EC private key.
     *
     * @param data data to sign.
     * @param privateKey EC public key
     * @return Array of bytes with signature or null in case of failure.
     */
    public static native byte[] ecdsaComputeSignature(byte[] data, EcPrivateKey privateKey);

    /**
     * Compute shared secret with using ECDH key-agreement.
     * @param publicKey Public key.
     * @param privateKey Private key.
     * @return Bytes with shared secret or null in case of failure.
     */
    public static native byte[] ecdhComputeSharedSecret(EcPublicKey publicKey, EcPrivateKey privateKey);

    /**
     * Computes SHA-256 from given data.
     *
     * @param data bytes to be hashed
     * @return bytes with SHA-256 result
     */
    public static native byte[] hashSha256(byte[] data);

    /**
     * Computes SHA-256 from given data and resize the result required length.
     *
     * @param data bytes to be hashed
     * @param resultLength Size of the returned array.
     * @return bytes with SHA-256 result. If new length is greater than 32, then returned array is padded with zeros.
     */
    public static byte[] hashSha256(byte[] data, int resultLength) {
        byte[] hash = hashSha256(data);
        return Arrays.copyOf(hash, resultLength);
    }

    /**
     * Compute HMAC-SHA-256 for given data and key.
     * @param data bytes with message
     * @param key bytes with key
     * @param outputLength Length of output MAC. If 0, then default length is used.
     * @return bytes with HMAC-SHA-256 result or {@code null} in case of failure.
     */
    public static native byte[] hmacSha256(byte[] data, byte[] key, int outputLength);

    /**
     * Compute HMAC-SHA-256 for given data and key.
     * @param data bytes with message
     * @param key bytes with key
     * @return bytes with HMAC-SHA-256 result or {@code null} in case of failure.
     */
    public static byte[] hmacSha256(byte[] data, byte[] key) {
        return hmacSha256(data, key, 0);
    }

    /**
     * Generate array of random bytes.
     * @param count number random bytes to generate.
     * @return random bytes or {@code null} in case of broken random generator or if provided
     *         count is negative.
     */
    public static native byte[] randomBytes(int count);

}
