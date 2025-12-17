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

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.ProtocolVersion.*;

/**
 * The <code>ProtocolVersion</code> enum defines PowerAuth protocol version. The main difference
 * between V2 &amp; V3 is that V3 is using hash-based counter instead of linear one,
 * and all E2EE tasks are now implemented by ECIES.
 * <p>
 * This version of SDK is supporting V2 protocol in very limited scope, where only
 * the V2 authorization code calculations are supported. Basically, you cannot connect
 * to V2 servers with V3 SDK.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({NA, V2, V3, V4})
public @interface ProtocolVersion {
    /**
     * Version is not available. This enumeration can be returned from some APIs,
     * when the value cannot be determined.
     */
    int NA = 0;

    /**
     * Protocol version 2
     */
    int V2 = 2;

    /**
     * Protocol version 3
     */
    int V3 = 3;

    /**
     * Protocol version 4
     */
    int V4 = 4;
}
