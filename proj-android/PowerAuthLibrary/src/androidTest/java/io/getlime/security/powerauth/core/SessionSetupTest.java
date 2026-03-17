/*
 * Copyright 2023 Wultra s.r.o.
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

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SessionSetupTest {
    @Test
    public void testValidV3Configuration() throws Exception {
        CoreConfig.validateConfiguration("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", CoreAlgorithm.LEGACY_P256);
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        assertThrows(CoreException.class, () -> CoreConfig.validateConfiguration("", CoreAlgorithm.LEGACY_P256));
        assertThrows(CoreException.class, () -> CoreConfig.validateConfiguration("", CoreAlgorithm.EC_P384));
        assertThrows(CoreException.class, () -> CoreConfig.validateConfiguration("", CoreAlgorithm.EC_P384_ML_L3));
        assertThrows(CoreException.class, () -> CoreConfig.validateConfiguration("", CoreAlgorithm.EC_P384_ML_L5));
    }
}
