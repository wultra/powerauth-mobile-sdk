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
 * Parameters for HTTP signature calculation.
 */
public class SignatureRequest {

    /**
     * A whole POST body or data blob prepared in 'Session.prepareKeyValueDictionaryForDataSigning'
     * method. You can also calculate signature for an empty request with no body or without
     * any GET parameters. In this case the member may be null.
     */
    public final byte[] body;
    /**
     * HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected)
     */
    public final String method;
    /**
     * Cryptographic constant for signature calculation. It's recommended to use relative HTTP path.
     */
    public final String uriIdentifier;
    /**
     * Optional, contains NONCE generated externally. The value should be used for offline data
     * signing purposes only. The Base64 string is expected.
     */
    public final String offlineNonce;
    /**
     * Length of offline signature component. The value is required and is validated only if
     * {@link #offlineNonce} is not {@code null}.
     */
    public final int offlineSignatureLength;

    /**
     * @param body bytes with HTTP request's body, or normalized bytes for GET requests
     * @param method HTTP method
     * @param uriIdentifier Cryptographic constant representing relative HTTP path
     * @param offlineNonce Optional nonce, required for offline signatures.
     * @param offlineSignatureLength Length of offline signature component.
     */
    public SignatureRequest(
            byte[] body,
            String method,
            String uriIdentifier,
            String offlineNonce,
            int offlineSignatureLength) {
        this.body = body;
        this.method = method;
        this.uriIdentifier = uriIdentifier;
        this.offlineNonce = offlineNonce;
        this.offlineSignatureLength = offlineSignatureLength;
    }
}
