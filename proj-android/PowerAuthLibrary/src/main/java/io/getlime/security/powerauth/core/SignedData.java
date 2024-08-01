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

package io.getlime.security.powerauth.core;

/**
 * The SignedData object contains data and signature calculated from data.
 */
public class SignedData {

    /**
     * A data protected with signature
     */
    public final byte[] data;
    /**
     * A signature calculated for data
     */
    public final byte[] signature;
    /**
     * Key to use for signature validation or computation.
     */
    @SigningDataKey
    public final int signingKey;

    /**
     * @param data data protected with signature
     * @param signature signature calculated for data
     * @param signingKey Key used to sign data, or will be used for the signature calculation.
     */
    public SignedData(byte[] data, byte[] signature, @SigningDataKey int signingKey) {
        this.data = data;
        this.signature = signature;
        this.signingKey = signingKey;
    }
}
