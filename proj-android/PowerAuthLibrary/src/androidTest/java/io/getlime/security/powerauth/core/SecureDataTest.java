/*
 * Copyright 2025 Wultra s.r.o.
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

import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.integration.support.RandomGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SecureDataTest {
    byte[] CLEANUP_16_OURS;
    byte[] CLEANUP_16_EXT;
    byte[] CLEANUP_24_OURS;
    byte[] CLEANUP_24_EXT;
    SecureData SECURE_16;       // reference data with original content
    SecureData SECURE_24;       // reference data with original content
    byte[] ORIG_16;             // reference data with original content
    byte[] ORIG_24;             // reference data with original content
    byte[] DATA_16;
    byte[] DATA_24;

    @Before
    public void setUp() {
        CLEANUP_16_OURS = new byte[16];
        CLEANUP_16_EXT = new byte[16];
        CLEANUP_24_OURS = new byte[24];
        CLEANUP_24_EXT = new byte[24];
        Arrays.fill(CLEANUP_16_OURS, SecureData.CLEAR_BYTE_OURS);
        Arrays.fill(CLEANUP_24_OURS, SecureData.CLEAR_BYTE_OURS);
        Arrays.fill(CLEANUP_16_EXT, SecureData.CLEAR_BYTE_OTHER);
        Arrays.fill(CLEANUP_24_EXT, SecureData.CLEAR_BYTE_OTHER);
        ORIG_16 = new RandomGenerator().generateBytes(16);
        ORIG_24 = new RandomGenerator().generateBytes(24);
        DATA_16 = Arrays.copyOf(ORIG_16, 16);
        DATA_24 = Arrays.copyOf(ORIG_24, 24);
        SECURE_16 = SecureData.copy(ORIG_16);
        SECURE_24 = SecureData.copy(ORIG_24);
    }

    @Test
    public void testCopy() {
        SecureData copy16 = SecureData.copy(DATA_16);
        SecureData copy24 = SecureData.copy(DATA_24);
        assertNotNull(copy16);
        assertNotNull(copy24);
        assertArrayEquals(DATA_16, copy16.getSensitiveData());
        assertArrayEquals(DATA_24, copy24.getSensitiveData());
        assertEquals(SECURE_16, copy16);
        assertEquals(SECURE_24, copy24);

        DATA_16[1] += 1;
        DATA_24[1] += 1;
        // Direct data compare should fail, because we modified DATA_15
        assertFalse(Arrays.equals(DATA_16, copy16.getSensitiveData()));
        assertFalse(Arrays.equals(DATA_24, copy24.getSensitiveData()));
        // Object compare should be OK, all secure data objects contains copy of original data.
        assertEquals(SECURE_16, copy16);
        assertEquals(SECURE_24, copy24);
        // Destroy
        copy16.destroy();
        copy24.destroy();
        assertNotEquals(SECURE_16, copy16);
        assertNotEquals(SECURE_24, copy24);
        assertArrayEquals(CLEANUP_16_OURS, copy16.getSensitiveData());
        assertArrayEquals(CLEANUP_24_OURS, copy24.getSensitiveData());
    }

    @Test
    public void testCopyAndClear() {
        SecureData copy16 = SecureData.copyAndClearSource(DATA_16);
        SecureData copy24 = SecureData.copyAndClearSource(DATA_24);
        assertNotNull(copy16);
        assertNotNull(copy24);
        assertArrayEquals(ORIG_16, copy16.getSensitiveData());
        assertArrayEquals(ORIG_24, copy24.getSensitiveData());
        assertArrayEquals(CLEANUP_16_EXT, DATA_16);
        assertArrayEquals(CLEANUP_24_EXT, DATA_24);
        assertEquals(SECURE_16, copy16);
        assertEquals(SECURE_24, copy24);

        // Object compare should be OK, all secure data objects contains copy of original data.
        assertEquals(SECURE_16, copy16);
        assertEquals(SECURE_24, copy24);

        copy16.destroy();
        copy24.destroy();
        assertNotEquals(SECURE_16, copy16);
        assertNotEquals(SECURE_24, copy24);
        assertArrayEquals(CLEANUP_16_OURS, copy16.getSensitiveData());
        assertArrayEquals(CLEANUP_24_OURS, copy24.getSensitiveData());
    }

    @Test
    public void testCapture() {
        SecureData cap16 = SecureData.capture(DATA_16);
        SecureData cap24 = SecureData.capture(DATA_24);
        assertNotNull(cap16);
        assertNotNull(cap24);
        assertEquals(DATA_16, cap16.getSensitiveData());
        assertEquals(DATA_24, cap24.getSensitiveData());
        assertEquals(SECURE_16, cap16);
        assertEquals(SECURE_24, cap24);

        DATA_16[1] += 1;
        DATA_24[1] += 1;
        // Direct data compare should not fail, the same arrays
        assertArrayEquals(DATA_16, cap16.getSensitiveData());
        assertArrayEquals(DATA_24, cap24.getSensitiveData());
        // Object compare fail, because cap16 and cap24 were modified
        assertNotEquals(SECURE_16, cap16);
        assertNotEquals(SECURE_24, cap24);

        cap16.destroy();
        cap24.destroy();
        assertNotEquals(SECURE_16, cap16);
        assertNotEquals(SECURE_24, cap24);
        assertArrayEquals(CLEANUP_16_OURS, cap16.getSensitiveData());
        assertArrayEquals(CLEANUP_24_OURS, cap24.getSensitiveData());
        assertArrayEquals(CLEANUP_16_OURS, DATA_16);
        assertArrayEquals(CLEANUP_24_OURS, DATA_24);
    }

    @Test
    public void testCreateNull() {
        assertNull(SecureData.capture(null));
        assertNull(SecureData.copy(null));
        assertNull(SecureData.copyAndClearSource(null));
    }
}
