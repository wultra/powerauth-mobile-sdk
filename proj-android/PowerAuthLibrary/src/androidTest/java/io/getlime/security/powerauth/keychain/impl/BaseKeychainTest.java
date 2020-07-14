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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import io.getlime.security.powerauth.keychain.Keychain;

import static org.junit.Assert.*;

public class BaseKeychainTest {

    // Test data

    public byte[] data_Empty;
    public byte[] data_NotEmpty;
    public final String string_Empty = "";
    public final String string_NotEmpty = "Hello world!";
    public Set<String> set_Empty;
    public Set<String> set_NotEmpty;

    public void setupTestData() {
        // Setup test data
        data_Empty = new byte[0];
        data_NotEmpty = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes();

        set_Empty = Collections.emptySet();
        set_NotEmpty = new HashSet<>();
        set_NotEmpty.add(string_Empty);
        set_NotEmpty.add(string_NotEmpty);
        set_NotEmpty.add("wultra.com");
    }

    public void fillTestValues(@NonNull Keychain keychain) throws Exception {
        keychain.putBoolean(true, "test.true");
        keychain.putBoolean(false, "test.false");
        keychain.putData(data_Empty, "test.data_Empty");
        keychain.putData(data_NotEmpty, "test.data_NotEmpty");
        keychain.putString(string_Empty, "test.string_Empty");
        keychain.putString(string_NotEmpty, "test.string_NotEmpty");
        keychain.putStringSet(set_Empty, "test.set_Empty");
        keychain.putStringSet(set_NotEmpty, "test.set_NotEmpty");
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
        assertArrayEquals(data_NotEmpty, keychain.getData("test.data_NotEmpty"));
        if (emptyStringIsNull) {
            assertNull(keychain.getString("test.string_Empty"));
        } else {
            assertEquals(string_Empty, keychain.getString("test.string_Empty", string_NotEmpty));
        }
        assertEquals(string_NotEmpty, keychain.getString("test.string_NotEmpty", string_Empty));
        final Set<String> emptySet = keychain.getStringSet("test.set_Empty");
        assertNotNull(emptySet);
        assertEquals(0, emptySet.size());
        final Set<String> notEmptySet = keychain.getStringSet("test.set_NotEmpty");
        assertNotNull(notEmptySet);
        assertEquals(3, notEmptySet.size());
        assertTrue(notEmptySet.contains(string_Empty));
        assertTrue(notEmptySet.contains(string_NotEmpty));
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
