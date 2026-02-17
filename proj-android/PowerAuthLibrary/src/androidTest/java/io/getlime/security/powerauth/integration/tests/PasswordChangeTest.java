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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.annotation.NonNull;

import org.junit.Test;

import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.networking.response.IBeginPasswordChangeListener;
import io.getlime.security.powerauth.networking.response.IChangePasswordListener;
import io.getlime.security.powerauth.networking.response.IFinishPasswordChangeListener;
import io.getlime.security.powerauth.networking.response.IValidatePasswordListener;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthPasswordChangeData;

/**
 * Test of password change functionality.
 */
public class PasswordChangeTest extends BaseTest {

    @Override
    public void setUp() throws Exception {
        super.setUp();
        activationHelper.createStandardActivation(false, null);
    }

    /**
     * Test correctness of the password validation helper methods.
     */
    @Test
    public void testPasswordCorrect() throws Exception {
        assertFalse(activationHelper.validateUserPassword(activationHelper.getInvalidPassword()));
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
    }

    /**
     * Test of the two step password change process using {@link Password} object.
     */
    @Test
    public void testTwoStepPasswordChange() throws Exception {
        final Password oldPassword = activationHelper.getValidPassword();
        final Password newPassword = new Password("nbusr321");

        assertTrue(activationHelper.validateUserPassword(oldPassword));
        assertFalse(activationHelper.validateUserPassword(newPassword));

        final PowerAuthPasswordChangeData passwordChangeData = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.beginPasswordChange(testHelper.getContext(), oldPassword, new IBeginPasswordChangeListener() {
                    @Override
                    public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                        resultCatcher.completeWithResult(passwordChangeData);
                    }

                    @Override
                    public void onBeginPasswordChangeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithError(throwable);
                    }
                }));

        boolean passwordChanged = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.finishPasswordChange(testHelper.getContext(), newPassword, passwordChangeData, new IFinishPasswordChangeListener() {
                    @Override
                    public void onFinishPasswordChangeSucceed() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onFinishPasswordChangeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertTrue(passwordChanged);

        assertTrue(activationHelper.validateUserPassword(newPassword));
        assertFalse(activationHelper.validateUserPassword(oldPassword));
    }

    /**
     * Test of the two step password change process using string password.
     */
    @Test
    public void testTwoStepPasswordChange_string() throws Exception {
        final String oldPassword = ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword());
        final String newPassword = "nbusr321";

        assertTrue(activationHelper.validateUserPassword(oldPassword));
        assertFalse(activationHelper.validateUserPassword(newPassword));

        final PowerAuthPasswordChangeData passwordChangeData = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.beginPasswordChange(testHelper.getContext(), oldPassword, new IBeginPasswordChangeListener() {
                    @Override
                    public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                        resultCatcher.completeWithResult(passwordChangeData);
                    }

                    @Override
                    public void onBeginPasswordChangeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithError(throwable);
                    }
                })
        );

        boolean passwordChanged = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.finishPasswordChange(testHelper.getContext(), newPassword, passwordChangeData, new IFinishPasswordChangeListener() {
                    @Override
                    public void onFinishPasswordChangeSucceed() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onFinishPasswordChangeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertTrue(passwordChanged);

        assertTrue(activationHelper.validateUserPassword(newPassword));
        assertFalse(activationHelper.validateUserPassword(oldPassword));
    }

    /**
     * Test of begin password change in case the method is called with wrong password.
     */
    @Test
    public void testBeginPasswordChange_wrongOldPassword() throws Exception {
        boolean succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.beginPasswordChange(testHelper.getContext(), activationHelper.getInvalidPassword(), new IBeginPasswordChangeListener() {
                    @Override
                    public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onBeginPasswordChangeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertFalse(succeeded);
    }

    /**
     * Test deprecated password change process approach using {@link Password} object.
     * @noinspection deprecation
     */
    @Test
    public void testChangePassword() throws Exception {
        final Password oldPassword = activationHelper.getValidPassword();
        final Password newPassword = new Password("nbusr321");

        assertTrue(activationHelper.validateUserPassword(oldPassword));
        assertFalse(activationHelper.validateUserPassword(newPassword));

        // Validate password using deprecated method
        boolean passwordValid = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.validatePassword(testHelper.getContext(), oldPassword, new IValidatePasswordListener() {
                    @Override
                    public void onPasswordValid() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordValidationFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertTrue(passwordValid);

        // Change the password using deprecated method
        boolean passwordChanged = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.changePassword(testHelper.getContext(), oldPassword, newPassword, new IChangePasswordListener() {
                    @Override
                    public void onPasswordChangeSucceed() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordChangeFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithResult(false);
                    }
                }));
        assertTrue(passwordChanged);

        assertTrue(activationHelper.validateUserPassword(newPassword));
        assertFalse(activationHelper.validateUserPassword(oldPassword));
    }

    /**
     * Test deprecated password change process approach using string password.
     * @noinspection deprecation
     */
    @Test
    public void testChangePassword_string() throws Exception {
        final String oldPassword = ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword());
        final String newPassword = "nbusr321";

        assertTrue(activationHelper.validateUserPassword(oldPassword));
        assertFalse(activationHelper.validateUserPassword(newPassword));

        // Validate password using deprecated method
        boolean passwordValid = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.validatePassword(testHelper.getContext(), oldPassword, new IValidatePasswordListener() {
                    @Override
                    public void onPasswordValid() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordValidationFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertTrue(passwordValid);

        // Change the password using deprecated method
        boolean passwordChanged = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.changePassword(testHelper.getContext(), oldPassword, newPassword, new IChangePasswordListener() {
                    @Override
                    public void onPasswordChangeSucceed() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordChangeFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithResult(false);
                    }
                }));
        assertTrue(passwordChanged);

        assertTrue(activationHelper.validateUserPassword(newPassword));
        assertFalse(activationHelper.validateUserPassword(oldPassword));
    }

    /**
     * Test that deprecated method to validate password fails on wrong password.
     * @noinspection deprecation
     */
    @Test
    public void testValidatePassword_wrongPassword() throws Exception {
        boolean passwordValid = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.validatePassword(testHelper.getContext(), activationHelper.getInvalidPassword(), new IValidatePasswordListener() {
                    @Override
                    public void onPasswordValid() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordValidationFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithResult(false);
                    }
                })
        );
        assertFalse(passwordValid);
    }

    /**
     * Test for deprecated method to unsafely change password.
     * @noinspection deprecation
     */
    @Test
    public void testChangePasswordUnsafe() throws Exception {
        final Password oldPassword = activationHelper.getValidPassword();
        final Password newPassword = new Password("nbusr321");

        if (getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256) {
            boolean passwordChanged = powerAuthSDK.changePasswordUnsafe(oldPassword, newPassword);
            assertTrue(passwordChanged);
            assertFalse(activationHelper.validateUserPassword(oldPassword));
            assertTrue(activationHelper.validateUserPassword(newPassword));
        } else {
            boolean passwordChanged = powerAuthSDK.changePasswordUnsafe(oldPassword, newPassword);
            assertFalse(passwordChanged);
            assertTrue(activationHelper.validateUserPassword(oldPassword));
            assertFalse(activationHelper.validateUserPassword(newPassword));
        }
    }

}
