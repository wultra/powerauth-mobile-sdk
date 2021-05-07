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

/**
 * The CryptoUtils class provides a several general cryptographic primitives
 * required in our other open source libraries.
 */
public class CryptoUtils {

    static {
        System.loadLibrary("PowerAuth2Module");
    }


    /**
     * Validates ECDSA signature for given data and EC public key.
     *
     * @param data signed data
     * @param signature signature calculated for data
     * @param publicKeyData EC public key
     * @return true if signature is valid
     */
    public static native boolean ecdsaValidateSignature(byte[] data, byte[] signature, byte[] publicKeyData);

    /**
     * Computes SHA-256 from given data.
     *
     * @param data bytes to be hashed
     * @return bytes with SHA-256 result
     */
    public static native byte[] hashSha256(byte[] data);

    /**
     * Compute HMAC-SHA-256 for given data and key.
     * @param data bytes with message
     * @param key bytes with key
     * @param outputLength Length of output MAC. If 0, then default length is used.
     * @return bytes with HMAC-SHA-256 result.
     */
    public static native byte[] hmacSha256(byte[] data, byte[] key, int outputLength);

    /**
     * Compute HMAC-SHA-256 for given data and key.
     * @param data bytes with message
     * @param key bytes with key
     * @return bytes with HMAC-SHA-256 result.
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
