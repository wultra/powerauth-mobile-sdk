/*
 * Copyright 2021 Wultra s.r.o.
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

package io.getlime.security.powerauth.keychain;

import io.getlime.security.powerauth.keychain.StrongBoxSupport;

/**
 * Testing implementation of {@link StrongBoxSupport} interface that can simulate StrongBox support
 * level during the unit test.
 */
public class FakeStrongBoxSupport implements StrongBoxSupport {

    private final boolean isSupported;
    private final boolean isEnabled;

    /**
     * Set StrongBox as not supported.
     */
    public FakeStrongBoxSupport() {
        isSupported = false;
        isEnabled = false;
    }

    /**
     * Set any combination of emulated StrongBox support.
     * @param supported Set StrongBox supported.
     * @param enabled Set StrongBox enabled.
     */
    public FakeStrongBoxSupport(boolean supported, boolean enabled) {
        isSupported = supported;
        isEnabled = enabled;
    }

    @Override
    public boolean isStrongBoxSupported() {
        return isSupported;
    }

    @Override
    public boolean isStrongBoxEnabled() {
        return isSupported && isEnabled;
    }
}
