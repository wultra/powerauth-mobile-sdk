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

package io.getlime.security.powerauth.networking.model.entity;

/**
 * The JwtHeader class represents a header in JWT signature.
 */
public class JwtHeader {
    /**
     * Type of object.
     */
    public final String typ;
    /**
     * Algorithm used in JWT.
     */
    public final String alg;

    /**
     * Construct object with JWT type and algorithm.
     * @param typ Type of JWT.
     * @param alg Algorithm used in JWT.
     */
    public JwtHeader(String typ, String alg) {
        this.typ = typ;
        this.alg = alg;
    }
}
