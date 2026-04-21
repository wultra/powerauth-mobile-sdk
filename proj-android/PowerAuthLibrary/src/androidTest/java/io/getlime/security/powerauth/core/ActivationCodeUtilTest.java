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

package io.getlime.security.powerauth.core;

import static org.junit.Assert.*;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class ActivationCodeUtilTest {

    @Test
    public void testValidateTypedCharacter() {
        // '2' - '7'
        for (int character = 50; character <= 55; character++) {
            assertTrue(ActivationCodeUtil.validateTypedCharacter(character));
        }
        // 'A' - 'Z'
        for (int character = 65; character <= 90; character++) {
            assertTrue(ActivationCodeUtil.validateTypedCharacter(character));
        }
        for (int character = -1; character < 50; character++) {
            assertFalse(ActivationCodeUtil.validateTypedCharacter(character));
        }
        for (int character = 56; character < 65; character++) {
            assertFalse(ActivationCodeUtil.validateTypedCharacter(character));
        }
        for (int character = 91; character < 512; character++) {
            assertFalse(ActivationCodeUtil.validateTypedCharacter(character));
        }
    }

    @Test
    public void testValidateAndCorrectTypedCharacter() {
        // '2' - '7'
        for (int character = 50; character <= 55; character++) {
            assertEquals(character, ActivationCodeUtil.validateAndCorrectTypedCharacter(character));
        }
        // 'A' - 'Z'
        for (int character = 65; character <= 90; character++) {
            assertEquals(character, ActivationCodeUtil.validateAndCorrectTypedCharacter(character));
        }
        // 'a' - 'z'
        for (int character = 97; character <= 122; character++) {
            assertEquals(character - 32, ActivationCodeUtil.validateAndCorrectTypedCharacter(character));
        }
        // '0' -> 'O'
        assertEquals(79, ActivationCodeUtil.validateAndCorrectTypedCharacter(48));
        // '1' -> 'I'
        assertEquals(73, ActivationCodeUtil.validateAndCorrectTypedCharacter(49));
    }

    @Test
    public void testValidateActivationCode() {
        final String[] validCodes = new String[] {
                // nice codes
                "AAAAA-AAAAA-AAAAA-AAAAA",
                "MMMMM-MMMMM-MMMMM-MUTOA",
                "VVVVV-VVVVV-VVVVV-VTFVA",
                "55555-55555-55555-55YMA",
                // random codes
                "W65WE-3T7VI-7FBS2-A4OYA",
                "DD7P5-SY4RW-XHSNB-GO52A",
                "X3TS3-TI35Z-JZDNT-TRPFA",
                "HCPJX-U4QC4-7UISL-NJYMA",
                "XHGSM-KYQDT-URE34-UZGWQ",
                "45AWJ-BVACS-SBWHS-ABANA",
                "BUSES-ETYN2-5HTFE-NOV2Q",
                "ATQAZ-WJ7ZG-FWA7J-QFAJQ",
                "MXSYF-LLQJ7-PS6LF-E2FMQ",
                "ZKMVN-4IMFK-FLSYX-ARRGA",
                "NQHGX-LNM2S-EQ4NT-G3NAA",
        };
        for (String code : validCodes) {
            assertTrue(ActivationCodeUtil.validateActivationCode(code));
        }
        final String[] invalidCodes = new String[] {
                "",
                "---",
                "AAAA-AAAAA-AAAAA-AAAAA",
                "AAAAA-AAAA-AAAAA-AAAAA",
                "AAAAA-AAAAA-AAAA-AAAAA",
                "AAAAA-AAAAA-AAAAA-AAAA",
                "     -     -     -     ",
                "AAAAA-AAAAA-AAAAA-AAAAB",
                "MMMMM-MMMMM-AMMMM-MUTOA",
                "VVVVV-VVXVV-VVVVV-VTFVA",
                "55555-55455-55555-55YMA",
                "ATQAZ-WJ7ZG-FWA6J-QFAJQ",
                "MXSYF-LBQJ7-PS6LF-E2FMQ",
                "ZKMVN-4IMFK-FLSXX-ARRGA",
                "NQHGX-LNM2S-FQ4NT-G3NAA",
                "NQHGXLNM2SEQ4NTG3NAA",
        };
        for (String code : invalidCodes) {
            assertFalse(ActivationCodeUtil.validateActivationCode(code));
        }
    }

    @Test
    public void testParseActivationCode() {
        ActivationCode parsed = ActivationCodeUtil.parseFromActivationCode("BBBBB-BBBBB-BBBBB-BTA6Q");
        assertNotNull(parsed);
        assertEquals("BBBBB-BBBBB-BBBBB-BTA6Q", parsed.activationCode);
        assertNull(parsed.activationSignature);
        parsed = ActivationCodeUtil.parseFromActivationCode("CCCCC-CCCCC-CCCCC-CNUUQ#ABCD");
        assertNotNull(parsed);
        assertEquals("CCCCC-CCCCC-CCCCC-CNUUQ", parsed.activationCode);
        assertEquals("ABCD", parsed.activationSignature);

        // Invalid
        assertNull(ActivationCodeUtil.parseFromActivationCode(""));
        assertNull(ActivationCodeUtil.parseFromActivationCode("#"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("W65WE-3T7VI-7FBS2-A4OYB"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("W65WE-3T7VI-7FBS2-A4OYB#ABCD"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("SSSSS-SSSSS-SSSSS-SX7IA#AB"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("UUUUU-UUUUU-UUUUU-UAFLQ#AB#"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("WWWWW-WWWWW-WWWWW-WNR7A#ABA=#"));
        assertNull(ActivationCodeUtil.parseFromActivationCode("XXXXX-XXXXX-XXXXX-X6RBQ#ABA-="));
    }
}
