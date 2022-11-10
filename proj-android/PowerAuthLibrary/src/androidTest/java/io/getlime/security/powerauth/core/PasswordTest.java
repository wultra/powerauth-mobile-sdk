/*
 * Copyright 2022 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.util.Arrays;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PasswordTest {

    @Test
    public void testImmutablePassword() {
        Password p1 = new Password("HelloWorld");
        assertFalse(p1.isMutable());
        assertEquals(10, p1.length());
        assertEquals("HelloWorld", extractStringFromPassword(p1));
        assertFalse(p1.clear());
        assertEquals(10, p1.length());

        Password p2 = new Password("HelloWorld");
        assertTrue(p1.isEqualToPassword(p2));

        p1.destroy();
        assertFalse(p1.isEqualToPassword(p2));
        p2.destroy();
        assertFalse(p1.isEqualToPassword(p2));

        Password p3 = new Password(new byte[] { 1, 2, 3, 4, 5, 6, 7 });
        assertFalse(p3.isMutable());
        assertEquals(7, p3.length());
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7 }, extractBytesFromPassword(p3));

        p3.destroy();
        assertEquals(0, p3.length());
    }

    @Test
    public void testMutableNumbers() {
        Password p1 = new Password();
        assertTrue(p1.isMutable());
        assertEquals(0, p1.length());

        assertTrue(p1.addCharacter(1));
        assertTrue(p1.insertCharacter(3, 1));
        assertTrue(p1.insertCharacter(0, 0));
        assertTrue(p1.insertCharacter(2, 2));
        assertTrue(p1.addCharacter(4));
        assertEquals(5, p1.length());
        assertEquals(new Password(new byte[] { 0, 1, 2, 3, 4}), p1);

        assertTrue(p1.removeCharacter(0));
        assertEquals(new Password(new byte[] { 1, 2, 3, 4}), p1);
        assertTrue(p1.removeCharacter(1));
        assertEquals(new Password(new byte[] { 1, 3, 4}), p1);
        assertTrue(p1.removeCharacter(2));
        assertEquals(new Password(new byte[] { 1, 3}), p1);
        assertTrue(p1.removeLastCharacter());
        assertTrue(p1.removeLastCharacter());

        // Out of range access
        assertFalse(p1.removeLastCharacter());
        assertFalse(p1.removeCharacter(0));
        assertFalse(p1.removeCharacter(1));
        assertFalse(p1.insertCharacter(11, 1));

        assertEquals(0, p1.length());
        assertTrue(p1.addCharacter(5));
        assertEquals(1, p1.length());

        assertTrue(p1.clear());
        assertEquals(0, p1.length());

        p1.destroy();
        assertEquals(0, p1.length());
        try {
            p1.validatePasswordComplexity(passwordBytes -> 0);
            fail();
        } catch (IllegalStateException exception) {
            // Success
        }
    }

    @Test
    public void testMutableUnicode() {
        Password p1 = new Password();
        assertTrue(p1.isMutable());

        assertTrue(p1.addCharacter('e'));
        assertTrue(p1.addCharacter('l'));
        assertTrue(p1.insertCharacter('l', 1));
        assertTrue(p1.insertCharacter('o', 3));
        assertTrue(p1.addCharacter('W'));
        assertTrue(p1.addCharacter('0'));
        assertTrue(p1.addCharacter('r'));
        assertTrue(p1.addCharacter('l'));
        assertTrue(p1.addCharacter('d'));
        assertTrue(p1.insertCharacter(0x397, 0));
        assertEquals(10, p1.length());
        assertEquals(11, extractBytesFromPassword(p1).length);
        assertEquals("ΗelloW0rld", extractStringFromPassword(p1));

        assertTrue(p1.removeCharacter(0));
        assertEquals("elloW0rld", extractStringFromPassword(p1));
        assertTrue(p1.removeLastCharacter());
        assertEquals("elloW0rl", extractStringFromPassword(p1));
        assertTrue(p1.insertCharacter(0x206, 1));
        assertEquals("eȆlloW0rl", extractStringFromPassword(p1));
        assertEquals(9, p1.length());
        assertTrue(p1.removeCharacter(5));
        assertEquals("eȆllo0rl", extractStringFromPassword(p1));
        assertTrue(p1.removeCharacter(1));
        assertEquals("ello0rl", extractStringFromPassword(p1));

        p1.destroy();
        assertEquals(0, p1.length());
        try {
            p1.validatePasswordComplexity(passwordBytes -> 0);
            fail();
        } catch (IllegalStateException exception) {
            // Success
        }
    }

    @Test
    public void testPasswordEqual()
    {
        Password p1 = new Password("fixed");
        Password p2 = new Password(new byte[] { 'f', 'i', 'x', 'e', 'd' });
        Password p3 = new Password();
        p3.addCharacter('f');
        p3.addCharacter('i');
        p3.addCharacter('x');
        p3.addCharacter('e');
        p3.addCharacter('d');

        assertEquals(p1, p1);
        assertEquals(p2, p2);
        assertEquals(p3, p3);
        assertEquals(p1, p2);
        assertEquals(p1, p3);
        assertEquals(p2, p3);
    }

    @Test
    public void testPasswordNotEqual()
    {
        Password p1 = new Password("fixed");
        Password p2 = new Password("strin");
        Password p3 = new Password("string");
        Password p4 = new Password("stri");
        Password p5 = new Password();

        assertFalse(p1.isEqualToPassword(p2));
        assertFalse(p1.isEqualToPassword(p3));
        assertFalse(p1.isEqualToPassword(p4));
        assertFalse(p1.isEqualToPassword(p5));
        assertFalse(p2.isEqualToPassword(p3));
        assertFalse(p2.isEqualToPassword(p4));
        assertFalse(p2.isEqualToPassword(p5));
        assertFalse(p3.isEqualToPassword(p4));
        assertFalse(p3.isEqualToPassword(p5));
        assertFalse(p4.isEqualToPassword(p5));

        assertNotEquals("fixed", p1);
        assertNotEquals(p1, "fixed");
    }

    @Test
    public void testPasswordCopy() {
        Password p1 = new Password("fixed");
        Password p2 = new Password(new byte[] { 'f', 'i', 'x', 'e', 'd' });
        Password p3 = new Password();
        Password p4 = new Password("tested");
        p3.addCharacter('f');
        p3.addCharacter('i');
        p3.addCharacter('x');
        p3.addCharacter('e');
        p3.addCharacter('d');
        p4.destroy();

        assertEquals(p1, p1);
        assertEquals(p2, p2);
        assertEquals(p3, p3);
        assertEquals(p1, p2);
        assertEquals(p1, p3);
        assertEquals(p2, p3);

        // Now make copy
        Password p1copy = p1.copyToImmutable();
        Password p2copy = p2.copyToImmutable();
        Password p3copy = p3.copyToImmutable();
        Password p4copy = p4.copyToImmutable();
        assertEquals(p1, p1copy);
        assertEquals(p2, p2copy);
        assertEquals(p3, p3copy);
        assertEquals(0, p4.length());
        assertNotEquals(p4, p4copy); // compare to destroyed is always false
    }

    private String extractStringFromPassword(Password password) {
        final String[] result = new String[1];
        password.validatePasswordComplexity(passwordBytes -> {
            result[0] = new String(passwordBytes, Charset.defaultCharset());
            return 0;
        });
        return result[0];
    }

    private byte[] extractBytesFromPassword(Password password) {
        final byte[][] result = new byte[1][1];
        password.validatePasswordComplexity(passwordBytes -> {
            result[0] = Arrays.copyOf(passwordBytes, passwordBytes.length);
            return 0;
        });
        return result[0];
    }
}
