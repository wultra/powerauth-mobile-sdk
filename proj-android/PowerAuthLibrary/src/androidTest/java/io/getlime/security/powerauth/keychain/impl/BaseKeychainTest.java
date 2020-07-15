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

import static org.junit.Assert.*;

public abstract class BaseKeychainTest {

    // Test data

    public static final byte[] TEST_DATA_EMPTY = new byte[0];
    public static final byte[] TEST_DATA_NOT_EMPTY = new byte[] { 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' , '!' };
    public static final String TEST_STRING_EMPTY = "";
    public static final String TEST_STRING_NOT_EMPTY = "Hello world!";
    public static final Set<String> TEST_SET_EMPTY = new HashSet<>();
    public static final Set<String> TEST_SET_NOT_EMPTY = new HashSet<>(Arrays.asList("This", "is", "test", "set", "wultra.com"));

    public void setupTestData() {
    }

    public void fillTestValues(@NonNull Keychain keychain) throws Exception {
        keychain.putBoolean(true, "test.true");
        keychain.putBoolean(false, "test.false");
        keychain.putData(TEST_DATA_EMPTY, "test.data_Empty");
        keychain.putData(TEST_DATA_NOT_EMPTY, "test.data_NotEmpty");
        keychain.putString(TEST_STRING_EMPTY, "test.string_Empty");
        keychain.putString(TEST_STRING_NOT_EMPTY, "test.string_NotEmpty");
        keychain.putStringSet(TEST_SET_EMPTY, "test.set_Empty");
        keychain.putStringSet(TEST_SET_NOT_EMPTY, "test.set_NotEmpty");
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
        assertArrayEquals(TEST_DATA_NOT_EMPTY, keychain.getData("test.data_NotEmpty"));
        if (emptyStringIsNull) {
            assertNull(keychain.getString("test.string_Empty"));
        } else {
            assertEquals(TEST_STRING_EMPTY, keychain.getString("test.string_Empty", TEST_STRING_NOT_EMPTY));
        }
        assertEquals(TEST_STRING_NOT_EMPTY, keychain.getString("test.string_NotEmpty", TEST_STRING_EMPTY));
        final Set<String> emptySet = keychain.getStringSet("test.set_Empty");
        assertNotNull(emptySet);
        assertEquals(0, emptySet.size());
        final Set<String> notEmptySet = keychain.getStringSet("test.set_NotEmpty");
        assertNotNull(notEmptySet);
        assertEquals(TEST_SET_NOT_EMPTY.size(), notEmptySet.size());
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
}
