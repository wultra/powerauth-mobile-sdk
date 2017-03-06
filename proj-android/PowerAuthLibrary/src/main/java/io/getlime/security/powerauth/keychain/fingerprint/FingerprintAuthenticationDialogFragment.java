/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.keychain.fingerprint;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import io.getlime.security.powerauth.R;

/**
 * Dialog fragment used for the purpose of Fingerprint authentication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintAuthenticationDialogFragment extends DialogFragment implements FingerprintCallback {

    private static final String ARG_TITLE = "arg_title";
    private static final String ARG_DESCRIPTION = "arg_description";
    private static final String ARG_BIOMETRIC_KEY = "arg_biometric_key";
    private static final String ARG_FORCE_GENERATE_NEW_KEY = "arg_force_generate_new_key";

    private static final String FINGERPRINT_DEFAULT_TAG = "FINGERPRINT_DEFAULT_TAG";

    static final long WRN_TIMEOUT_MILLIS = 1600;
    static final long SUCCESS_DELAY_MILLIS = 800;

    private ImageView mImgIcon;
    private TextView mTxtStatus;
    private TextView mTxtDescription;
    private IFingerprintActionHandler mAuthenticationCallback;

    private FingerprintAuthenticationHandler mFingerprintAuthenticationHandler;
    private FingerprintStage mStage;

    private FragmentManager fragmentManager;

    private boolean mSelfCancelled;

    /**
     * Builder class used to construct the 'FingerprintAuthenticationDialogFragment' instance.
     */
    public static class DialogFragmentBuilder {

        private String title;
        private String description;
        private byte[] biometricKey;
        private boolean forceGenerateNewKey;

        /**
         * Set dialog title.
         * @param title Dialog title.
         * @return Self-reference.
         */
        public DialogFragmentBuilder title(String title) {
            this.title = title;
            return this;
        }

        /**
         * Set dialog description.
         * @param description Dialog description.
         * @return Self-reference.
         */
        public DialogFragmentBuilder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * Set biometric key.
         * @param biometricKey biometric key.
         * @return Self-reference.
         */
        public DialogFragmentBuilder biometricKey(byte[] biometricKey) {
            this.biometricKey = biometricKey;
            return this;
        }

        public DialogFragmentBuilder forceGenerateNewKey(boolean forceGenerateNewKey) {
            this.forceGenerateNewKey = forceGenerateNewKey;
            return this;
        }

        /**
         * Build the new fingerprint authentication dialog fragment.
         * @return New fingerprint authentication dialog fragment.
         */
        public FingerprintAuthenticationDialogFragment build() {
            FingerprintAuthenticationDialogFragment dialogFragment = new FingerprintAuthenticationDialogFragment();
            Bundle bundle = new Bundle();
            bundle.putString(ARG_TITLE, title);
            bundle.putString(ARG_DESCRIPTION, description);
            bundle.putByteArray(ARG_BIOMETRIC_KEY, biometricKey);
            bundle.putBoolean(ARG_FORCE_GENERATE_NEW_KEY, forceGenerateNewKey);
            dialogFragment.setArguments(bundle);
            dialogFragment.setCancelable(false);
            return dialogFragment;
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mFingerprintAuthenticationHandler = new FingerprintAuthenticationHandler.FingerprintHelperBuilder(getContext())
                .forceGenerateNewKey(getArguments().getBoolean(ARG_FORCE_GENERATE_NEW_KEY, false))
                .callback(this)
                .build();
        mStage = mFingerprintAuthenticationHandler.initCrypto();
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {

        AlertDialog.Builder alertBuilder = new AlertDialog.Builder(getActivity());

        if (mStage.equals(FingerprintStage.USE_FINGERPRINT)) {

            alertBuilder.setTitle(getArguments().getString(ARG_TITLE));
            alertBuilder.setPositiveButton(R.string.close, new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int i) {
                    if (mAuthenticationCallback != null) {
                        mAuthenticationCallback.onFingerprintDialogCancelled();
                    }
                    dismiss();
                }
            });

            LayoutInflater layoutInflater = getActivity().getLayoutInflater();
            @SuppressLint("InflateParams") // AlertDialog => null is OK in this case
            View view = layoutInflater.inflate(R.layout.dialog_fingerprint_login, null);

            mImgIcon = (ImageView) view.findViewById(R.id.fingerprint_icon);
            mTxtStatus = (TextView) view.findViewById(R.id.fingerprint_status);
            mTxtDescription = (TextView) view.findViewById(R.id.fingerprint_description);

            alertBuilder.setView(view);

            mTxtDescription.setText(getArguments().getString(ARG_DESCRIPTION));

        } else if (mStage.equals(FingerprintStage.INFO_ENROLL_NEW_FINGERPRINT)) {

            mFingerprintAuthenticationHandler.stopListening();
            mFingerprintAuthenticationHandler.removeKey();

            alertBuilder.setTitle(R.string.fingerprint_dialog_title_new_fingerprint);
            alertBuilder.setMessage(R.string.fingerprint_dialog_description_new_fingerprint);
            alertBuilder.setIcon(R.drawable.ic_fingerprint_error);
            alertBuilder.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int i) {
                    if (mAuthenticationCallback != null) {
                        mAuthenticationCallback.onFingerprintInfoDialogClosed();
                    }
                    dismiss();
                }
            });

        } else if (mStage.equals(FingerprintStage.INFO_FINGERPRINT_NOT_AVAILABLE)) {

            mFingerprintAuthenticationHandler.stopListening();
            mFingerprintAuthenticationHandler.removeKey();

            alertBuilder.setTitle(R.string.fingerprint_dialog_title_no_scanner);
            alertBuilder.setMessage(R.string.fingerprint_dialog_description_no_scanner);
            alertBuilder.setIcon(R.drawable.ic_fingerprint_error);
            alertBuilder.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int i) {
                    if (mAuthenticationCallback != null) {
                        mAuthenticationCallback.onFingerprintInfoDialogClosed();
                    }
                    dismiss();
                }
            });

        } else if (mStage.equals(FingerprintStage.INFO_FINGERPRINT_INVALIDATED)) {

            mFingerprintAuthenticationHandler.stopListening();
            mFingerprintAuthenticationHandler.removeKey();

            alertBuilder.setTitle(R.string.fingerprint_dialog_title_invalidated);
            alertBuilder.setMessage(R.string.fingerprint_dialog_description_invalidated);
            alertBuilder.setIcon(R.drawable.ic_fingerprint_error);
            alertBuilder.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int i) {
                    if (mAuthenticationCallback != null) {
                        mAuthenticationCallback.onFingerprintInfoDialogClosed();
                    }
                    dismiss();
                }
            });

        }

        final AlertDialog alertDialog = alertBuilder.create();

        // Customize Dialog Appearance
        alertDialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface arg0) {
                int COLOR_BUTTON_POSITIVE = getContext().getColor(R.color.color_fingerprint_close_button);
                alertDialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(COLOR_BUTTON_POSITIVE);
            }
        });

        return alertDialog;
    }

    @Override
    public void onResume() {
        super.onResume();
        mSelfCancelled = false;
        if (mStage.equals(FingerprintStage.USE_FINGERPRINT)) {
            mFingerprintAuthenticationHandler.startListening();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        mSelfCancelled = true;
        mFingerprintAuthenticationHandler.stopListening();
        dismiss();
    }

    @Override
    public void onAuthenticated() {
        if (isAdded()) {
            showSuccess();
        }
    }

    @Override
    public void onAuthenticationHelp(CharSequence helpString) {
        if (isAdded()) {
            showWarning(helpString);
        }
    }

    @Override
    public void onAuthenticationFailed() {
        if (isAdded()) {
            showWarning(getString(R.string.fingerprint_dialog_not_recognized));
        }
    }

    @Override
    public void onAuthenticationError(CharSequence errString) {
        if (isAdded()) {
            if (!mSelfCancelled) {
                showError(errString);
            }
        }
    }

    /**
     * Set an authentication callback.
     * @param authCallback Callback called after the authentication result is known.
     */
    public void setAuthenticationCallback(IFingerprintActionHandler authCallback) {
        this.mAuthenticationCallback = authCallback;
    }

    /**
     * Setter for the fragment manager.
     * @param fragmentManager Fragment manager.
     */
    public void setFragmentManager(FragmentManager fragmentManager) {
        this.fragmentManager = fragmentManager;
    }

    /**
     * Show the dialog.
     */
    public void show() {
        this.show(fragmentManager, FINGERPRINT_DEFAULT_TAG);
    }

    /**
     * Show a success state.
     */
    protected void showSuccess() {
        mTxtStatus.removeCallbacks(mResetErrorTextRunnable);
        mImgIcon.setImageResource(R.drawable.ic_fingerprint_success);
        mTxtStatus.setText(getString(R.string.fingerprint_dialog_success));
        mTxtStatus.setTextColor(getContext().getColor(R.color.color_fingerprint_success_text));
        mImgIcon.postDelayed(new Runnable() {

            @Override
            public void run() {
                if (mAuthenticationCallback != null) {
                    final byte[] biometricKey = getArguments().getByteArray(ARG_BIOMETRIC_KEY);
                    if (biometricKey != null) {
                        byte[] encrypted = mFingerprintAuthenticationHandler.encryptedKey(biometricKey);
                        if (encrypted != null) {
                            mAuthenticationCallback.onFingerprintDialogSuccess(encrypted);
                        } else {
                            mAuthenticationCallback.onFingerprintDialogSuccess(null);
                        }
                    } else {
                        mAuthenticationCallback.onFingerprintDialogSuccess(null);
                    }
                }
                dismiss();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    /**
     * Show error message.
     * @param error Error message.
     */
    protected void showError(CharSequence error) {
        mImgIcon.setImageResource(R.drawable.ic_fingerprint_error);
        mTxtStatus.setText(error);
        mTxtStatus.setTextColor(getContext().getColor(R.color.color_fingerprint_failure_text));
        mTxtStatus.removeCallbacks(mResetErrorTextRunnable);
    }

    /**
     * Show warning message.
     * @param error Warning message.
     */
    protected void showWarning(CharSequence error) {
        mImgIcon.setImageResource(R.drawable.ic_fingerprint_error);
        mTxtStatus.setText(error);
        mTxtStatus.setTextColor(getContext().getColor(R.color.color_fingerprint_failure_text));
        mTxtStatus.removeCallbacks(mResetErrorTextRunnable);
        mTxtStatus.postDelayed(mResetErrorTextRunnable, WRN_TIMEOUT_MILLIS);
    }

    private final Runnable mResetErrorTextRunnable = new Runnable() {

        @Override
        public void run() {
            if (isAdded()) {
                mTxtStatus.setText(mTxtStatus.getResources().getString(R.string.fingerprint_dialog_touch_sensor));
                mImgIcon.setImageResource(R.drawable.ic_fingerprint_default);
                mTxtStatus.setTextColor(getContext().getColor(R.color.color_fingerprint_text_secondary));
            }
        }
    };

}
