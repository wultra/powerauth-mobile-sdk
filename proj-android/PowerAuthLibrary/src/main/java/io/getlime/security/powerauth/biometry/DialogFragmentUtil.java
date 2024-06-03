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
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package io.getlime.security.powerauth.biometry;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

/**
 * Utility methods for `DialogFragment`.
 */
public class DialogFragmentUtil {

    /**
     * A utility method to show dialog safely when `android.app.Activity#onSaveInstanceState(Bundle)` was already called.
     */
    public static void showDialogAllowingStateLoss(@NonNull DialogFragment dialogFragment, @NonNull FragmentManager manager, @Nullable String tag) {
        final FragmentTransaction ft = manager.beginTransaction();
        ft.setReorderingAllowed(true);
        ft.add(dialogFragment, tag);
        // cannot commit() to avoid java.lang.IllegalStateException when onSaveInstanceState() was already called
        ft.commitAllowingStateLoss();
    }
}
