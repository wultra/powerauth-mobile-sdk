/*
 * Copyright 2026 Wultra s.r.o.
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

import static io.getlime.security.powerauth.core.CoreActivationState.*;

/**
 * The {@code CoreActivationState} enum defines all possible states of activation.
 * The state is a part of information received together with the rest of the
 * {@link io.getlime.security.powerauth.core.response.CoreActivationStatus} object.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({PENDING_COMMIT, ACTIVE, BLOCKED, REMOVED, DEADLOCK})
public @interface CoreActivationState {
    /**
     * The activation is not completed yet on the server.
     */
    int PENDING_COMMIT = 0;
    /**
     * The activation is valid and active.
     */
    int ACTIVE = 1;
    /**
     * The activation is blocked.
     */
    int BLOCKED = 2;
    /**
     * The activation doesn't exist anymore.
     */
    int REMOVED = 3;
    /**
     * The activation is technically blocked. You cannot use it anymore for the authentication code
     * calculations.
     */
    int DEADLOCK = 4;
}
