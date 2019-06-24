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

package io.getlime.security.powerauth.biometry.impl.legacy;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.ColorInt;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.annotation.StringRes;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.FragmentManager;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import io.getlime.security.powerauth.biometry.FingerprintDialogResources;

/**
 * Dialog fragment used for the purpose of fallback Fingerprint authentication.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintAuthenticationDialogFragment extends DialogFragment implements FingerprintAuthenticationHandler.ProgressListener {

    private static final String ARG_RESOURCES = "arg_resources";
    private static final String ARG_TITLE = "arg_title";
    private static final String ARG_DESCRIPTION = "arg_description";

    private static final String FINGERPRINT_DEFAULT_TAG = "FINGERPRINT_DEFAULT_TAG";

    static final long WRN_TIMEOUT_MILLIS = 1600;
    static final long SUCCESS_DELAY_MILLIS = 800;

    private boolean mIsAuthenticated;

    private ImageView mImgIcon;
    private TextView mTxtStatus;
    private TextView mTxtDescription;
    private FingerprintDialogResources mResources;

    /**
     * Builder class used to construct the {@link FingerprintAuthenticationDialogFragment} instance.
     */
    public static class Builder {

        private final @NonNull Context context;

        private CharSequence title;
        private CharSequence description;
        private FingerprintDialogResources resources;

        public Builder(@NonNull Context context) {
            this.context = context;
        }

        /**
         * Set dialog title.
         * @param title Dialog title.
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
         * Set dialog description.
         * @param description Dialog description.
         * @return Self-reference.
         */
        public Builder setDescription(@NonNull CharSequence description) {
            this.description = description;
            return this;
        }

        /**
         * Set dialog description.
         * @param descriptionId Dialog description.
         * @return Self-reference.
         */
        public Builder setDescription(@StringRes int descriptionId) {
            this.description = context.getText(descriptionId);
            return this;
        }

        /**
         * Set static dialog resources.
         * @param resources {@link FingerprintDialogResources} object with dialog's static resources.
         * @return Self-reference.
         */
        public Builder setDialogResources(@NonNull FingerprintDialogResources resources) {
            this.resources = resources;
            return this;
        }

        /**
         * Build the new fingerprint authentication dialog fragment.
         *
         * @return New fingerprint authentication dialog fragment.
         */
        public FingerprintAuthenticationDialogFragment build() {
            if (title == null || description == null) {
                throw new IllegalArgumentException("Title or description parameter is missing.");
            }
            if (resources == null) {
                throw new IllegalArgumentException("Dialog resources parameter is missing.");
            }
            final FingerprintAuthenticationDialogFragment dialogFragment = new FingerprintAuthenticationDialogFragment();
            final Bundle bundle = new Bundle();
            bundle.putCharSequence(ARG_TITLE, title);
            bundle.putCharSequence(ARG_DESCRIPTION, description);
            bundle.putIntArray(ARG_RESOURCES, resources.packResources());
            dialogFragment.setArguments(bundle);
            dialogFragment.setCancelable(false);
            return dialogFragment;
        }
    }

    // Override methods

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Unpack mode & resources from the dialog
        final Bundle bundle = getArguments();
        if (bundle != null) {
            mResources = FingerprintDialogResources.unpackResources(bundle.getIntArray(ARG_RESOURCES));
        }
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {

        final Bundle bundle = getArguments();
        final Activity activity = getActivity();

        if (activity == null || bundle == null) {
            throw new IllegalStateException("Activity or dialog arguments are missing.");
        }
        final Context context = activity.getApplicationContext();

        AlertDialog.Builder alertBuilder = new AlertDialog.Builder(getActivity());

        final LayoutInflater layoutInflater = activity.getLayoutInflater();
        final View view = layoutInflater.inflate(mResources.layout.dialogLayout, null);

        // Look for views
        mImgIcon = (ImageView) view.findViewById(mResources.layout.statusImageView);
        mTxtStatus = (TextView) view.findViewById(mResources.layout.statusTextView);
        mTxtDescription = (TextView) view.findViewById(mResources.layout.descriptionTextView);

        // Configure views
        view.setBackgroundResource(mResources.colors.background);

        alertBuilder.setTitle(bundle.getCharSequence(ARG_TITLE));
        mTxtDescription.setText(bundle.getCharSequence(ARG_DESCRIPTION));
        mTxtDescription.setTextColor(context.getColor(mResources.colors.primaryText));

        mTxtStatus.setText(mResources.strings.statusTouchSensor);
        mTxtStatus.setTextColor(context.getColor(mResources.colors.secondaryText));

        mImgIcon.setImageResource(mResources.drawables.fingerprintIcon);

        alertBuilder.setPositiveButton(mResources.strings.close, new DialogInterface.OnClickListener() {

            @Override
            public void onClick(DialogInterface dialog, int i) {
                reportResult();
            }
        });

        alertBuilder.setView(view);

        final AlertDialog alertDialog = alertBuilder.create();

        // Customize Dialog Appearance
        alertDialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface dialogInterface) {
                if (FingerprintAuthenticationDialogFragment.this.isAdded()) {
                    @ColorInt int color = alertDialog.getContext().getColor(mResources.colors.closeButtonText);
                    alertDialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(color);
                }
            }
        });

        // Handle back button in dialog
        alertDialog.setOnKeyListener(new Dialog.OnKeyListener() {
            @Override
            public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                if (keyCode == KeyEvent.KEYCODE_BACK) {
                    reportResult();
                }
                return true;
            }
        });

        return alertDialog;
    }

    // DialogFragment methods

    @Override
    public void onResume() {
        super.onResume();
        if (mHandler != null) {
            mHandler.startListening();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        if (mHandler != null) {
            mHandler.stopListening();
        }
        reportResult();
    }

    @Override
    public void onDismiss(DialogInterface dialog) {
        super.onDismiss(dialog);
        // Release the progress listener from the handler, to avoid a potential memory leak.
        // We still need to keep a handler to report the completion.
        if (mHandler != null) {
            mHandler.removeProgressListener();
        }
    }

    // FingerprintAuthenticationHandler.ProgressListener methods

    /**
     * Error message reported from the {@link FingerprintAuthenticationHandler}
     */
    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        if (isAdded()) {
            showError(errString);
        }
    }

    /**
     * Help message reported from the {@link FingerprintAuthenticationHandler}
     */
    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        if (isAdded()) {
            showWarning(helpString);
        }
    }

    /**
     * Authentication failure reported from the {@link FingerprintAuthenticationHandler}
     */
    @Override
    public void onAuthenticationFailed() {
        if (isAdded()) {
            showWarning(getContext().getText(mResources.strings.statusFingerprintNotRecognized));
        }
    }

    /**
     * Authentication success reported from the {@link FingerprintAuthenticationHandler}
     */
    @Override
    public void onAuthenticationSuccess() {
        if (isAdded()) {
            showSuccess();
        }
    }

    // Private state handling

    /**
     * Report result to the {@link FingerprintAuthenticationHandler} and dismiss the dialog.
     * The reported result depends on the state and the mode of the dialog. If dialog is
     * in "AUTHENTICATION" mode, then the method reports "cancel", unless the fingerprint
     * authentication already succeeded. For "SHOW_ERROR" mode, the method always reports
     * the result, because the result is already configured in the handler itself.
     */
    private void reportResult() {
        if (mHandler != null) {
            if (mIsAuthenticated) {
                mHandler.reportResult();
            } else {
                mHandler.reportCancel();
            }
        }
        dismiss();
    }

    /**
     * Show error message to the status text view.
     *
     * @param error Error to be displayed.
     */
    private void showError(CharSequence error) {
        final Context context = getContext();
        if (mIsAuthenticated || context == null) {
            return;
        }
        mImgIcon.setImageResource(mResources.drawables.errorIcon);
        mTxtStatus.setText(error);
        mTxtStatus.setTextColor(context.getColor(mResources.colors.failureText));
        mTxtStatus.removeCallbacks(mResetStatusTextRunnable);
    }

    /**
     * Show warning message in the status text view and then, after a short pause, set status
     * back to the default text.
     *
     * @param warning Message to be displayed.
     */
    private void showWarning(CharSequence warning) {
        final Context context = getContext();
        if (mIsAuthenticated || context == null) {
            return;
        }
        mImgIcon.setImageResource(mResources.drawables.errorIcon);
        mTxtStatus.setText(warning);
        mTxtStatus.setTextColor(context.getColor(mResources.colors.failureText));
        mTxtStatus.removeCallbacks(mResetStatusTextRunnable);
        mTxtStatus.postDelayed(mResetStatusTextRunnable, WRN_TIMEOUT_MILLIS);
    }

    /**
     * Show success message to the status text view and then, after some delay, report the result
     * to the {@link FingerprintAuthenticationHandler}.
     */
    private void showSuccess() {
        // Mark that this dialog has already the result.
        mIsAuthenticated = true;
        // Configure status
        mImgIcon.setImageResource(mResources.drawables.successIcon);
        mTxtStatus.setText(mResources.strings.statusSuccess);
        mTxtStatus.setTextColor(getContext().getColor(mResources.colors.successText));
        mImgIcon.postDelayed(new Runnable() {
            @Override
            public void run() {
                reportResult();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    /**
     * Property contains Runnable closure which resets mTxtStatus to the default prompt text.
     */
    private final Runnable mResetStatusTextRunnable = new Runnable() {

        @Override
        public void run() {
            final Context context = getContext();
            if (isAdded() && context != null) {
                mTxtStatus.setText(mResources.strings.statusTouchSensor);
                mImgIcon.setImageResource(mResources.drawables.fingerprintIcon);
                mTxtStatus.setTextColor(getContext().getColor(mResources.colors.secondaryText));
            }
        }
    };

    /**
     * Contains reference to handler which manages fingerprint scanning process.
     */
    private @Nullable FingerprintAuthenticationHandler mHandler;

    /**
     * Sets handler to this dialog. The property is not kept in the dialog Bundle arguments.
     *
     * This is known design anti-patter for fragments, but this authentication dialog should never
     * be restored from the saved state. The reason for that is that the dialog is automatically
     * dismissed in {@code onPause()} method.
     *
     * @param handler Handler managing fingerprint scanning process.
     */
    public void setFingerprintAuthenticationHandler(@NonNull FingerprintAuthenticationHandler handler) {
        this.mHandler = handler;
    }

    /**
     * Shows dialog fragment.
     * @param fragmentManager {@link FragmentManager} responsible for dialog presentation.
     */
    public void show(@NonNull FragmentManager fragmentManager) {
        this.show(fragmentManager, FINGERPRINT_DEFAULT_TAG);
    }

}
