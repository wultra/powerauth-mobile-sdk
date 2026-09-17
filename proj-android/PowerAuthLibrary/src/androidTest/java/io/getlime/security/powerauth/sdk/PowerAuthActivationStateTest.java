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

package io.getlime.security.powerauth.sdk;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class PowerAuthActivationStateTest {

    @Test
    public void activationStateInternalValues() {
        // These ordinals should remain compatible with PowerAuth SDK 1.9.x.
        assertEquals(2, PowerAuthActivationState.PENDING_COMMIT);
        assertEquals(3, PowerAuthActivationState.ACTIVE);
        assertEquals(4, PowerAuthActivationState.BLOCKED);
        assertEquals(5, PowerAuthActivationState.REMOVED);
        assertEquals(128, PowerAuthActivationState.DEADLOCK);
    }
}
