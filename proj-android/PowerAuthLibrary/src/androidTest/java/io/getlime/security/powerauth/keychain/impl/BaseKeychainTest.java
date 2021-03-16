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

package io.getlime.security.powerauth.keychain.impl;

import android.support.annotation.NonNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.system.PA2Log;

import static org.junit.Assert.*;

public abstract class BaseKeychainTest {

    // Test data

    public static final byte[] TEST_DATA_EMPTY = new byte[0];
    public static final byte[] TEST_DATA_NOT_EMPTY_1 = new byte[] { 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' , '!' };
    public static final byte[] TEST_DATA_NOT_EMPTY_2 = new byte[] { 'n', 'b', 'u', 's', 'r', '1', '2', '3' };
    public static final String TEST_STRING_EMPTY = "";
    public static final String TEST_STRING_NOT_EMPTY_1 = "Hello world!";
    public static final String TEST_STRING_NOT_EMPTY_2 = "Just hello...";
    public static final String TEST_STRING_BAD_BASE64 = "a==";

    public static final Set<String> TEST_SET_EMPTY = new HashSet<>();
    public static final Set<String> TEST_SET_NOT_EMPTY_1 = new HashSet<>(Arrays.asList("This", "is", "test", "set", "wultra.com"));
    public static final Set<String> TEST_SET_NOT_EMPTY_2 = new HashSet<>(Arrays.asList("hash", "set"));

    public void setupTestData() {
        PA2Log.setEnabled(true);
        PA2Log.setVerbose(true);
    }

    /**
     * Run all standard tests with provided keychain implementation.
     * @param keychain Keychain object to test.
     * @throws Exception In case of failure.
     */
    public void runAllStandardTests(@NonNull Keychain keychain) throws Exception {
        fillTestValues(keychain);
        runAllStandardValidations(keychain, false);
    }

    /**
     * Run all standard validations on provided keychain implementation. The keychain must be filled
     * with {@link #fillTestValues(Keychain)} method.
     * @param keychain Keychain object to test.
     * @param emptyStringIsNull Set {@code true} if it's expected that empty string is treated as {@code null}.
     *                          This is expected for an encrypted keychains.
     * @throws Exception In case of failure.
     */
    public void runAllStandardValidations(@NonNull Keychain keychain, boolean emptyStringIsNull) throws Exception {
        testFilledValues(keychain, emptyStringIsNull);
        testDefaultValues(keychain);
        testNullValueToRemoveKey(keychain);
        testUpdateData(keychain);
    }

    /**
     * Fill keychain with test values.
     * @param keychain Keychain object to fill with data.
     * @throws Exception In case of failure.
     */
    public void fillTestValues(@NonNull Keychain keychain) throws Exception {
        keychain.putBoolean(true, "test.true");
        keychain.putBoolean(false, "test.false");
        keychain.putData(TEST_DATA_EMPTY, "test.data_Empty");
        keychain.putData(TEST_DATA_NOT_EMPTY_1, "test.data_NotEmpty");
        keychain.putString(TEST_STRING_EMPTY, "test.string_Empty");
        keychain.putString(TEST_STRING_NOT_EMPTY_1, "test.string_NotEmpty");
        keychain.putString(TEST_STRING_BAD_BASE64, "test.string_BadBase64");
        keychain.putStringSet(TEST_SET_EMPTY, "test.set_Empty");
        keychain.putStringSet(TEST_SET_NOT_EMPTY_1, "test.set_NotEmpty");
        keychain.putFloat(0.f, "test.zeroFloat");
        keychain.putFloat(-99.f, "test.negativeFloat");
        keychain.putFloat( 3.14159f, "test.positiveFloat");
        keychain.putLong(0, "test.zeroLong");
        keychain.putLong(7710177, "test.long");
        keychain.putLong(-303, "test.negativeLong");
    }

    public void testFilledValues(@NonNull Keychain keychain, boolean emptyStringIsNull) throws Exception {
        assertTrue(keychain.getBoolean("test.true", false));
        assertFalse(keychain.getBoolean("test.false", true));
        assertNull(keychain.getData("test.data_Empty"));
        assertArrayEquals(TEST_DATA_NOT_EMPTY_1, keychain.getData("test.data_NotEmpty"));
        if (emptyStringIsNull) {
            assertNull(keychain.getString("test.string_Empty"));
        } else {
            assertEquals(TEST_STRING_EMPTY, keychain.getString("test.string_Empty", TEST_STRING_NOT_EMPTY_1));
        }
        assertEquals(TEST_STRING_NOT_EMPTY_1, keychain.getString("test.string_NotEmpty", TEST_STRING_EMPTY));
        assertEquals(TEST_STRING_BAD_BASE64, keychain.getString("test.string_BadBase64", TEST_STRING_EMPTY));
        final Set<String> emptySet = keychain.getStringSet("test.set_Empty");
        assertNotNull(emptySet);
        assertEquals(0, emptySet.size());
        final Set<String> notEmptySet = keychain.getStringSet("test.set_NotEmpty");
        assertNotNull(notEmptySet);
        assertEquals(TEST_SET_NOT_EMPTY_1.size(), notEmptySet.size());
        assertTrue(notEmptySet.contains("This"));
        assertTrue(notEmptySet.contains("is"));
        assertTrue(notEmptySet.contains("test"));
        assertTrue(notEmptySet.contains("set"));
        assertTrue(notEmptySet.contains("wultra.com"));
        assertEquals(0.f, keychain.getFloat("test.zeroFloat", -1f), 0.0);
        assertEquals(-99.f, keychain.getFloat("test.negativeFloat", 0.f), 0.0);
        assertEquals(3.14159f, keychain.getFloat("test.positiveFloat", 0.f), 0.0);
        assertEquals(0, keychain.getLong("test.zeroLong", -1));
        assertEquals(7710177, keychain.getLong("test.long", 0));
        assertEquals(-303, keychain.getLong("test.negativeLong", 0));
    }

    public void testDefaultValues(@NonNull Keychain keychain) throws Exception {
        assertTrue(keychain.getBoolean("test.unknownKey", true));
        assertEquals(101, keychain.getLong("test.unknownKey", 101));
        assertEquals("default", keychain.getString("test.unknownKey", "default"));
        assertEquals(6.44f, keychain.getFloat("test.unknownKey", 6.44f), 0.0);
        assertNull(keychain.getData("test.unknownKey"));
        assertNull(keychain.getString("test.unknownKey"));
        assertNull(keychain.getStringSet("test.unknownKey"));
    }

    public void testNullValueToRemoveKey(@NonNull Keychain keychain) throws Exception {
        fillTestValues(keychain);
        keychain.putString(null, "test.string_NotEmpty");
        assertFalse(keychain.contains("test.string_NotEmpty"));
        keychain.putData(null, "test.data_NotEmpty");
        assertFalse(keychain.contains("test.data_NotEmpty"));
        keychain.putStringSet(null, "test.set_NotEmpty");
        assertFalse(keychain.contains("test.set_NotEmpty"));
    }

    public void testUpdateData(@NonNull Keychain keychain) throws Exception {
        fillTestValues(keychain);

        keychain.putBoolean(false, "test.true");
        keychain.putData(TEST_DATA_NOT_EMPTY_2, "test.data_NotEmpty");
        keychain.putString(TEST_STRING_NOT_EMPTY_2, "test.string_NotEmpty");
        keychain.putStringSet(TEST_SET_NOT_EMPTY_2, "test.set_NotEmpty");
        keychain.putFloat(1.f, "test.zeroFloat");
        keychain.putLong(1, "test.zeroLong");

        assertFalse(keychain.getBoolean("test.true", true));
        assertArrayEquals(TEST_DATA_NOT_EMPTY_2, keychain.getData("test.data_NotEmpty"));
        assertEquals(TEST_STRING_NOT_EMPTY_2, keychain.getString("test.string_NotEmpty"));
        assertEquals(1.f, keychain.getFloat("test.zeroFloat", 0.f), 0.0);
        assertEquals(1, keychain.getLong("test.zeroLong", 0));
        final Set<String> receivedSet = keychain.getStringSet("test.set_NotEmpty");
        assertNotNull(receivedSet);
        assertTrue(receivedSet.contains("hash"));
        assertTrue(receivedSet.contains("set"));
        assertFalse(receivedSet.contains("This"));
        assertFalse(receivedSet.contains("is"));
        assertFalse(receivedSet.contains("test"));
        assertFalse(receivedSet.contains("wultra.com"));
    }
}
