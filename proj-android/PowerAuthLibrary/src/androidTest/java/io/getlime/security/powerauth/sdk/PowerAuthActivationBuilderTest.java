/*
 * Copyright 2020 Wultra s.r.o.
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

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.HashMap;
import java.util.Map;

import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.model.entity.ActivationType;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthActivationBuilderTest {

    // Standard activations

    @Test
    public void createStandardActivation() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYA", null)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CODE, activation.activationType);
        assertNotNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("code"));
        assertNull(activation.activationCode.activationSignature);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.activationCode.activationCode);
        assertNull(activation.activationName);
        assertNull(activation.additionalActivationOtp);
    }

    @Test
    public void createStandardActivationWithSignature() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYA#MEYCIQDvw4Peeka5cwZJld3IBJJpF3U6OHZP7iva+JpiBxiqfAIhAIj9ZEXLoGlHxVSJHZbRhUJEuhSTrt647lNKXQ30PAQ0", null)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CODE, activation.activationType);
        assertNotNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("code"));
        assertEquals("MEYCIQDvw4Peeka5cwZJld3IBJJpF3U6OHZP7iva+JpiBxiqfAIhAIj9ZEXLoGlHxVSJHZbRhUJEuhSTrt647lNKXQ30PAQ0", activation.activationCode.activationSignature);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.activationCode.activationCode);
        assertNull(activation.activationName);
        assertNull(activation.additionalActivationOtp);
    }

    @Test
    public void createStandardActivationWithName() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYA", "Named activation")
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CODE, activation.activationType);
        assertNotNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.activationCode.activationCode);
        assertEquals("Named activation", activation.activationName);
        assertNull(activation.additionalActivationOtp);
    }

    @Test
    public void createStandardActivationWithExtras() throws Exception {
        Map<String, Object> additionalAttributes = new HashMap<>();
        additionalAttributes.put("test", "value");
        additionalAttributes.put("zero", 0);

        PowerAuthActivation activation = PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYA", "Named activation")
                .setExtras("extras")
                .setCustomAttributes(additionalAttributes)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CODE, activation.activationType);
        assertNotNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.activationCode.activationCode);
        assertEquals("Named activation", activation.activationName);
        assertEquals("extras", activation.extras);
        assertNotNull(activation.customAttributes);
        assertEquals(0, activation.customAttributes.get("zero"));
        assertEquals("value", activation.customAttributes.get("test"));
        assertNull(activation.additionalActivationOtp);
    }

    @Test
    public void createStandardActivationWithOtp() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYA", "Named activation")
                .setExtras("extras")
                .setAdditionalActivationOtp("12345")
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CODE, activation.activationType);
        assertNotNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.activationCode.activationCode);
        assertEquals("Named activation", activation.activationName);
        assertEquals("extras", activation.extras);
        assertEquals("12345", activation.additionalActivationOtp);
    }

    @Test(expected = PowerAuthErrorException.class)
    public void createStandardActivationWithInvalidCode() throws Exception {
        PowerAuthActivation.Builder.activation("W65WE-3T7VI-7FBS2-A4OYB", null)
                .build();
    }

    // Recovery activations

    @Test
    public void createRecoveryActivation() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYA", "1234567890", null)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.RECOVERY, activation.activationType);
        assertNotNull(activation.identityAttributes);
        assertEquals("1234567890", activation.identityAttributes.get("puk"));
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("recoveryCode"));
        assertNull(activation.activationName);
    }

    @Test
    public void createRecoveryActivationFromQrCode() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.recoveryActivation("R:W65WE-3T7VI-7FBS2-A4OYA", "1234567890", null)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.RECOVERY, activation.activationType);
        assertNotNull(activation.identityAttributes);
        assertEquals("1234567890", activation.identityAttributes.get("puk"));
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("recoveryCode"));
        assertNull(activation.activationName);
    }

    @Test
    public void createRecoveryActivationWithName() throws Exception {
        PowerAuthActivation activation = PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYA", "1234567890", "Recovery")
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.RECOVERY, activation.activationType);
        assertNotNull(activation.identityAttributes);
        assertEquals("1234567890", activation.identityAttributes.get("puk"));
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("recoveryCode"));
        assertEquals("Recovery", activation.activationName);
    }

    @Test
    public void createRecoveryActivationWithExtras() throws Exception {
        Map<String, Object> additionalAttributes = new HashMap<>();
        additionalAttributes.put("test", "value");
        additionalAttributes.put("zero", 0);

        PowerAuthActivation activation = PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYA", "1234567890", "Recovery")
                .setExtras("extras")
                .setCustomAttributes(additionalAttributes)
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.RECOVERY, activation.activationType);
        assertNotNull(activation.identityAttributes);
        assertEquals("1234567890", activation.identityAttributes.get("puk"));
        assertEquals("W65WE-3T7VI-7FBS2-A4OYA", activation.identityAttributes.get("recoveryCode"));
        assertEquals("Recovery", activation.activationName);
        assertEquals("extras", activation.extras);
        assertNotNull(activation.customAttributes);
        assertEquals(0, activation.customAttributes.get("zero"));
        assertEquals("value", activation.customAttributes.get("test"));
    }

    @Test(expected = PowerAuthErrorException.class)
    public void createRecoveryActivationWithOtp() throws Exception {
        PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYA", "1234567890", "Recovery")
                .setAdditionalActivationOtp("1234")
                .build();
    }

    @Test(expected = PowerAuthErrorException.class)
    public void createRecoveryActivationWithInvalidCode() throws Exception {
        PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYB", "1234567890", null)
                .build();
    }

    @Test(expected = PowerAuthErrorException.class)
    public void createRecoveryActivationWithInvalidPuk() throws Exception {
        PowerAuthActivation.Builder.recoveryActivation("W65WE-3T7VI-7FBS2-A4OYA", "123456789", null)
                .build();
    }

    // Custom activation

    @Test
    public void createCustomActivation() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("login", "juraj");
        identityAttributes.put("password", "nbusr123");

        PowerAuthActivation activation = PowerAuthActivation.Builder.customActivation(identityAttributes, null)
                .build();

        assertNotNull(activation);
        assertNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("juraj", activation.identityAttributes.get("login"));
        assertEquals("nbusr123", activation.identityAttributes.get("password"));
        assertNull(activation.activationName);
        assertEquals(ActivationType.CUSTOM, activation.activationType);
    }

    @Test
    public void createCustomActivationWithName() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("login", "juraj");
        identityAttributes.put("password", "nbusr123");

        PowerAuthActivation activation = PowerAuthActivation.Builder.customActivation(identityAttributes, "CustomActivation")
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CUSTOM, activation.activationType);
        assertNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("juraj", activation.identityAttributes.get("login"));
        assertEquals("nbusr123", activation.identityAttributes.get("password"));
        assertEquals("CustomActivation", activation.activationName);
    }

    @Test
    public void createCustomActivationWitExtras() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("login", "juraj");
        identityAttributes.put("password", "nbusr123");
        Map<String, Object> additionalAttributes = new HashMap<>();
        additionalAttributes.put("test", "value");
        additionalAttributes.put("zero", 0);

        PowerAuthActivation activation = PowerAuthActivation.Builder.customActivation(identityAttributes, "CustomActivation")
                .setCustomAttributes(additionalAttributes)
                .setExtras("extras")
                .build();

        assertNotNull(activation);
        assertEquals(ActivationType.CUSTOM, activation.activationType);
        assertNull(activation.activationCode);
        assertNotNull(activation.identityAttributes);
        assertEquals("juraj", activation.identityAttributes.get("login"));
        assertEquals("nbusr123", activation.identityAttributes.get("password"));
        assertEquals("CustomActivation", activation.activationName);
        assertEquals("extras", activation.extras);
        assertNotNull(activation.customAttributes);
        assertEquals(0, activation.customAttributes.get("zero"));
        assertEquals("value", activation.customAttributes.get("test"));
    }

    @Test(expected = PowerAuthErrorException.class)
    public void createCustomActivationWithOtp() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("login", "juraj");
        identityAttributes.put("password", "nbusr123");

        PowerAuthActivation activation = PowerAuthActivation.Builder.customActivation(identityAttributes, "CustomActivation")
                .setAdditionalActivationOtp("1234")
                .build();
    }
}
