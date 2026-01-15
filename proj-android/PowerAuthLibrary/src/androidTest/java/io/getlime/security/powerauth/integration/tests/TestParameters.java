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

package io.getlime.security.powerauth.integration.tests;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestParameters {
    public static Iterable<Object[]> getParameters() {
        List<Object[]> out = new ArrayList<>();
        for (String algorithm : Arrays.asList(
                "LEGACY_P256",
                "EC_P384",
                "EC_P384_ML_L3",
                "EC_P384_ML_L5")) {
            out.add(new Object[]{ algorithm });
        }
        return out;
    }
}
