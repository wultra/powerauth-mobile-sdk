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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

/**
 * The {@code FragmentHelper} object contains an instance of {@link Fragment} or {@link FragmentActivity},
 * depending on what application does provide for the displaying dialogs or similar UI elements.
 */
public class FragmentHelper {

    final @Nullable Fragment fragment;
    final @Nullable FragmentActivity fragmentActivity;

    /**
     * Construct object with either fragment or fragment activity.
     * @param fragment {@link Fragment} instance.
     * @param fragmentActivity {@link FragmentActivity} instance.
     */
    private FragmentHelper(@Nullable Fragment fragment, @Nullable FragmentActivity fragmentActivity) {
        this.fragment = fragment;
        this.fragmentActivity = fragmentActivity;
    }

    /**
     * Construct helper with {@link Fragment} instance.
     * @param fragment {@link Fragment} instance.
     * @return Instance of fragment helper containing {@link Fragment}.
     */
    public static @NonNull FragmentHelper from(@NonNull Fragment fragment) {
        return new FragmentHelper(fragment, null);
    }

    /**
     * Construct helper with {@link Fragment} instance.
     * @param fragmentActivity {@link FragmentActivity} instance.
     * @return Instance of fragment helper containing {@link FragmentActivity}.
     */
    public static @NonNull FragmentHelper from(@NonNull FragmentActivity fragmentActivity) {
        return new FragmentHelper(null, fragmentActivity);
    }

    /**
     * @return {@link Fragment} instance or {@code null} in case that helper contains
     *         {@link FragmentActivity}.
     */
    public @Nullable Fragment getFragment() {
        return fragment;
    }

    /**
     * @return {@link FragmentActivity} instance or {@code null} in case that helper contains
     *         {@link Fragment}.
     */
    public @Nullable FragmentActivity getFragmentActivity() {
        return fragmentActivity;
    }
}
