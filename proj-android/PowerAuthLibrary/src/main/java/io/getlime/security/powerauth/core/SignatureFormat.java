/*
 * Copyright 2024 Wultra s.r.o.
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

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.SignatureFormat.DEFAULT;
import static io.getlime.security.powerauth.core.SignatureFormat.ECDSA_DER;
import static io.getlime.security.powerauth.core.SignatureFormat.ECDSA_JOSE;

/**
 * The {@code SignatureFormat} enumeration defines signature type expected at input, or produced at output.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({DEFAULT, ECDSA_DER, ECDSA_JOSE})
public @interface SignatureFormat {
    /**
     * If default signature is used, then `ECDSA_DER` is used for ECDSA signature. The raw bytes are always used for
     * HMAC signatures.
     */
    int DEFAULT = 0;
    /**
     * ECDSA signature in DER format is expected at input, or produced at output:
     *  <pre>
     *  ASN.1 notation:
     *  ECDSASignature ::= SEQUENCE {
     *     r   INTEGER,
     *     s   INTEGER
     * }
     * </pre>
     */
    int ECDSA_DER = 1;
    /**
     * ECDSA signature in JOSE format is epxpected at input, or produced at output.
     */
    int ECDSA_JOSE = 2;
}
