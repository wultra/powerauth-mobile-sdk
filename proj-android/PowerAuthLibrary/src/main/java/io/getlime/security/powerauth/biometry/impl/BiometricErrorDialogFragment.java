/*
 * Copyright 2019 Wultra s.r.o.
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

package io.getlime.security.powerauth.biometry.impl;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.fragment.app.DialogFragment;

/**
 * Dialog fragment displaying the error message when biometric authentication cannot be used.
 */
public class BiometricErrorDialogFragment extends DialogFragment {

    private static final String ARG_TITLE = "arg_title";
    private static final String ARG_MESSAGE = "arg_message";
    private static final String ARG_CLOSE_BUTTON_TEXT = "arg_close_btn_text";
    private static final String ARG_ERROR_ICON = "arg_error_icon";

    public static final String FRAGMENT_DEFAULT_TAG = "BIOMETRIC_ERROR_DEFAULT_TAG";

    /**
     * Listener for receive a dialog close event.
     */
    public interface OnCloseListener {
        /**
         * Called when dialog is closed.
         */
        void onClose();
    }

    /**
     * Builder class used to construct {@link BiometricErrorDialogFragment} instance.
     */
    public static class Builder {

        private final @NonNull Context context;
        private CharSequence title;
        private CharSequence message;
        private CharSequence closeButton;
        private @DrawableRes int errorIcon;
        private OnCloseListener onCloseListener;

        /**
         * Construct builder class that provides {@link BiometricErrorDialogFragment} instance.
         * @param context Android {@link Context} instance.
         */
        public Builder(@NonNull Context context) {
            this.context = context;
        }

        /**
         * Set dialog title.
         * @param title Dialog title
         * @return Self-reference.
         */
        public Builder setTitle(@NonNull CharSequence title) {
            this.title = title;
            return this;
        }

        /**
         * Set dialog title.
         * @param titleId Dialog title
         * @return Self-reference.
         */
        public Builder setTitle(@StringRes int titleId) {
            this.title = context.getText(titleId);
            return this;
        }

        /**
         * Set dialog message;
         * @param message Dialog message
         * @return Self-reference.
         */
        public Builder setMessage(@NonNull CharSequence message) {
            this.message = message;
            return this;
        }

        /**
         * Set dialog message;
         * @param messageId Dialog message
         * @return Self-reference.
         */
        public Builder setMessage(@StringRes int messageId) {
            this.message = context.getText(messageId);
            return this;
        }

        /**
         * Set icon to the dialog.
         * @param iconId Icon image.
         * @return Self-reference.
         */
        public Builder setIcon(@DrawableRes int iconId) {
            this.errorIcon = iconId;
            return this;
        }

        /**
         * Set close button text and color.
         * @param closeButton Close button text
         * @return Self-reference.
         */
        public Builder setCloseButton(@NonNull CharSequence closeButton) {
            this.closeButton = closeButton;
            return this;
        }

        /**
         * Set close button text and color.
         * @param closeButtonId Close button text
         * @return Self-reference.
         */
        public Builder setCloseButton(@StringRes int closeButtonId) {
            this.closeButton = context.getText(closeButtonId);
            return this;
        }

        /**
         * Set listener that receive close event.
         * @param listener {@link OnCloseListener} that receive close event.
         * @return Self-reference.
         */
        public Builder setOnCloseListener(@NonNull OnCloseListener listener) {
            this.onCloseListener = listener;
            return this;
        }

        /**
         * Build the new error dialog fragment.
         * @return New error dialog fragment.
         */
        public BiometricErrorDialogFragment build() {
            if (title == null || message == null || closeButton == null) {
                throw new IllegalArgumentException("Required string is missing.");
            }
            if (errorIcon == 0) {
                throw new IllegalArgumentException("Icon resource is missing.");
            }
            if (onCloseListener == null) {
                throw new IllegalArgumentException("OnCloseListener is not set.");
            }

            final BiometricErrorDialogFragment fragment = new BiometricErrorDialogFragment();

            final Bundle arguments = new Bundle();
            arguments.putCharSequence(ARG_TITLE, title);
            arguments.putCharSequence(ARG_MESSAGE, message);
            arguments.putCharSequence(ARG_CLOSE_BUTTON_TEXT, closeButton);
            arguments.putInt(ARG_ERROR_ICON, errorIcon);
            fragment.setArguments(arguments);

            fragment.setOnCloseListener(onCloseListener);
            fragment.setRetainInstance(true);

            return fragment;

        }
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {

        final Bundle arguments = getArguments();

        AlertDialog.Builder alertBuilder = new AlertDialog.Builder(getActivity());

        alertBuilder.setTitle(arguments.getCharSequence(ARG_TITLE));
        alertBuilder.setMessage(arguments.getCharSequence(ARG_MESSAGE));
        alertBuilder.setIcon(arguments.getInt(ARG_ERROR_ICON));
        alertBuilder.setPositiveButton(arguments.getCharSequence(ARG_CLOSE_BUTTON_TEXT), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int i) {
                dismissAllowingStateLoss();
            }
        });

        // Create the dialog.
        return alertBuilder.create();
    }

    @Override
    public void onDismiss(@NonNull DialogInterface dialog) {
        super.onDismiss(dialog);
        reportClose();
    }

    /**
     * Contains listener called when the alert is closed
     */
    private OnCloseListener onCloseListener;

    /**
     * Set {@link OnCloseListener} object to the dialog fragment.
     * @param listener Listener object to be set.
     */
    private void setOnCloseListener(@NonNull OnCloseListener listener) {
        onCloseListener = listener;
    }

    /**
     * Report close of the dialog into the listener.
     */
    private void reportClose() {
        // Report close, only for once
        if (onCloseListener != null) {
            onCloseListener.onClose();
            onCloseListener = null;
        }
    }
}
