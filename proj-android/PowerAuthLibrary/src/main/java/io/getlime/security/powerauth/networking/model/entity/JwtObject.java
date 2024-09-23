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
 * The JwtObject represents JWT request and response.
 */
public class JwtObject {

    /**
     * Full JWT formatted string
     */
    public final String jwt;

    /**
     * Construct object with JWT formatted string.
     * @param jwt JWT formatted string.
     */
    public JwtObject(String jwt) {
        this.jwt = jwt;
    }
}
