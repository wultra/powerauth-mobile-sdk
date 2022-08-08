/*
 * Copyright 2021 Wultra s.r.o.
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

#include <cc7tests/CC7Tests.h>
#include <PowerAuth/OtpUtil.h>

// Required by "nice code generator"
#include <cc7/Base32.h>
#include <cc7/Endian.h>
#include "../PowerAuth/utils/CRC16.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2OtpUtilTests : public UnitTest
    {
    public:
        
        pa2OtpUtilTests()
        {
            CC7_REGISTER_TEST_METHOD(testActivationCodeValidation)
            CC7_REGISTER_TEST_METHOD(testCharValidation)
            CC7_REGISTER_TEST_METHOD(testCharAutocorrection)
            CC7_REGISTER_TEST_METHOD(testActivationCodeParser)
            CC7_REGISTER_TEST_METHOD(testRecoveryCodeValidation)
            CC7_REGISTER_TEST_METHOD(testRecoveryPukValidation)
            CC7_REGISTER_TEST_METHOD(testRecoveryCodeParser)
            CC7_REGISTER_TEST_METHOD(niceCodeGenerator)
        }
        
        
        // unit tests

        void testActivationCodeValidation()
        {
            const char * valid_codes[] = {
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
                NULL
            };
            const char ** p = valid_codes;
            while (const char * code = *p++) {
                bool result = OtpUtil::validateActivationCode(std::string(code));
                ccstAssertTrue(result, "Code '%s' should pass the test", code);
            }
            
            const char * invalid_codes[] = {
                "",
                " ",
                "KLMNO-PQRST",
                "KLMNO-PQRST-UVWXY-Z234",
                "KLMNO-PQRST-UVWXY-Z2345 ",
                "KLMNO-PQRST-UVWXY-Z2345#",
                "67AAA-B0BCC-DDEEF-GGHHI"
                "67AAA-BB1CC-DDEEF-GGHHI",
                "67AAA-BBBC8-DDEEF-GGHHI",
                "67AAA-BBBCC-DDEEF-GGHH9",
                "67aAA-BBBCC-DDEEF-GGHHI",
                "6-AAA-BB1CC-DDEEF-GGHHI",
                "67AA#-BB1CC-DDEEF-GGHHI",
                "67AABCBB1CC-DDEEF-GGHHI",
                "67AAB-BB1CCEDDEEF-GGHHI",
                "67AAA-BBBCC-DDEEFZGGHHI",
                NULL
            };
            p = invalid_codes;
            while (const char * code = *p++) {
                bool result = OtpUtil::validateActivationCode(std::string(code));
                ccstAssertFalse(result, "Code '%s' should not pass the test", code);
            }

        }
        
        
        void testCharAutocorrection()
        {
            const char * valid_translations[] = {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                "abcdefghijklmnopqrstuvwxyz01",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZOI",
                NULL, NULL
            };
            const char ** p = valid_translations;
            while (*p) {
                std::string inp = *p++;
                std::string out = *p++;
                ccstAssertTrue(inp.length() == out.length());
                for (size_t i = 0; i < inp.length(); i++) {
                    cc7::U32 inp_char = (cc7::U32)inp[i];
                    cc7::U32 out_char = (cc7::U32)out[i];
                    cc7::U32 cor_char = OtpUtil::validateAndCorrectTypedCharacter(inp_char);
                    ccstAssertEqual(out_char, cor_char, "Corrected characted doesn't match '%c'->'%c' != '%c'", inp_char, out_char, cor_char)
                }
            }
            
            std::string invalid_characters("89-=#$%^&!@#-=';()");
            for (size_t i = 0; i < invalid_characters.length(); i++) {
                cc7::U32 inp_char = (cc7::U32)invalid_characters[i];
                cc7::U32 cor_char = OtpUtil::validateAndCorrectTypedCharacter(inp_char);
                ccstAssertEqual(0, cor_char, "Character '%c' should not pass validation", inp_char);
            }
        }
        
        
        void testCharValidation()
        {
            std::string valid_characters("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
            for (size_t i = 0; i < valid_characters.length(); i++) {
                cc7::U32 inp_char = (cc7::U32)valid_characters[i];
                bool result = OtpUtil::validateTypedCharacter(inp_char);
                ccstAssertTrue(result, "Character '%c' should pass validation", inp_char);
            }
            
            std::string invalid_characters("abcdefghijklmnopqrstuvwxyz0189-=#$%^&!@#-=';()");
            for (size_t i = 0; i < invalid_characters.length(); i++) {
                cc7::U32 inp_char = (cc7::U32)invalid_characters[i];
                bool result = OtpUtil::validateTypedCharacter(inp_char);
                ccstAssertFalse(result, "Character '%c' should not pass validation", inp_char);
            }
        }
        
        
        void testActivationCodeParser()
        {
            OtpComponents components;
            bool result;
            
            // valid sequences
            result = OtpUtil::parseActivationCode("BBBBB-BBBBB-BBBBB-BTA6Q", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "BBBBB-BBBBB-BBBBB-BTA6Q");
            ccstAssertEqual(components.activationSignature, "");
            ccstAssertFalse(components.hasSignature());
            
            result = OtpUtil::parseActivationCode("CCCCC-CCCCC-CCCCC-CNUUQ#ABCD", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "CCCCC-CCCCC-CCCCC-CNUUQ");
            ccstAssertEqual(components.activationSignature, "ABCD");
            ccstAssertTrue(components.hasSignature());
            
            result = OtpUtil::parseActivationCode("DDDDD-DDDDD-DDDDD-D6UKA#ABC=", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "DDDDD-DDDDD-DDDDD-D6UKA");
            ccstAssertEqual(components.activationSignature, "ABC=");
            ccstAssertTrue(components.hasSignature());

            result = OtpUtil::parseActivationCode("EEEEE-EEEEE-EEEEE-E2OXA#AB==", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "EEEEE-EEEEE-EEEEE-E2OXA");
            ccstAssertEqual(components.activationSignature, "AB==");
            ccstAssertTrue(components.hasSignature());

            
            // invalid sequences
            result = OtpUtil::parseActivationCode("", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("#AB==", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("KLMNO-PQRST", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("EEEEE-EEEEE-EEEEE-E2OXA#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("OOOOO-OOOOO-OOOOO-OZH2Q#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("SSSSS-SSSSS-SSSSS-SX7IA#AB", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("UUUUU-UUUUU-UUUUU-UAFLQ#AB#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("WWWWW-WWWWW-WWWWW-WNR7A#ABA=#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseActivationCode("XXXXX-XXXXX-XXXXX-X6RBQ#ABA-=", components);
            ccstAssertFalse(result);
        }

        
        void testRecoveryCodeValidation()
        {
            const char * valid_codes[] = {
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

                // With R: prefix
                "R:AAAAA-AAAAA-AAAAA-AAAAA",
                "R:MMMMM-MMMMM-MMMMM-MUTOA",
                "R:VVVVV-VVVVV-VVVVV-VTFVA",
                "R:55555-55555-55555-55YMA",
                "R:BUSES-ETYN2-5HTFE-NOV2Q",
                "R:ATQAZ-WJ7ZG-FWA7J-QFAJQ",
                "R:MXSYF-LLQJ7-PS6LF-E2FMQ",
                "R:ZKMVN-4IMFK-FLSYX-ARRGA",
                "R:NQHGX-LNM2S-EQ4NT-G3NAA",
                NULL
            };
            const char ** p = valid_codes;
            while (const char * code = *p++) {
                bool result = OtpUtil::validateRecoveryCode(std::string(code));
                ccstAssertTrue(result, "Code '%s' should pass the test", code);
            }
            
            const char * invalid_codes[] = {
                "",
                " ",
                "R",
                "R:",
                "X:AAAAA-AAAAA-AAAAA-AAAAA",
                "KLMNO-PQRST",
                "R:KLMNO-PQRST",
                "KLMNO-PQRST-UVWXY-Z234",
                "KLMNO-PQRST-UVWXY-Z2345 ",
                "R:KLMNO-PQRST-UVWXY-Z2345 ",
                "KLMNO-PQRST-UVWXY-Z2345#",
                "NQHGX-LNM2S-EQ4NT-G3NAA#aGVsbG8td29ybGQ=",
                "R:NQHGX-LNM2S-EQ4NT-G3NAA#aGVsbG8td29ybGQ=",
                "67AAA-B0BCC-DDEEF-GGHHI"
                "67AAA-BB1CC-DDEEF-GGHHI",
                "67AAA-BBBC8-DDEEF-GGHHI",
                "67AAA-BBBCC-DDEEF-GGHH9",
                "67aAA-BBBCC-DDEEF-GGHHI",
                "6-AAA-BB1CC-DDEEF-GGHHI",
                "67AA#-BB1CC-DDEEF-GGHHI",
                "67AABCBB1CC-DDEEF-GGHHI",
                "67AAB-BB1CCEDDEEF-GGHHI",
                "67AAA-BBBCC-DDEEFZGGHHI",
                NULL
            };
            p = invalid_codes;
            while (const char * code = *p++) {
                bool result = OtpUtil::validateRecoveryCode(std::string(code));
                ccstAssertFalse(result, "Code '%s' should not pass the test", code);
            }
            
            ccstAssertTrue(OtpUtil::validateRecoveryCode("NQHGX-LNM2S-EQ4NT-G3NAA", false));
            ccstAssertFalse(OtpUtil::validateRecoveryCode("R:NQHGX-LNM2S-EQ4NT-G3NAA", false));
        }
        
        void testRecoveryPukValidation()
        {
            const char * valid_puks[] = {
                "0000000000",
                "9999999999",
                "0123456789",
                "9876543210",
                "1111111111",
                "3487628763",
                NULL
            };
            const char ** p = valid_puks;
            while (const char * puk = *p++) {
                bool result = OtpUtil::validateRecoveryPuk(std::string(puk));
                ccstAssertTrue(result, "PUK '%s' should pass the test", puk);
            }
            
            const char * invalid_puks[] = {
                "",
                " ",
                "11111111111",
                "111111111",
                "0",
                "999999999A",
                "99999999b9",
                "9999999c99",
                "999999d999",
                "99999e9999",
                "9999f99999",
                "999g999999",
                "99h9999999",
                "9i99999999",
                "A999999999",
                "999999999 ",
                "99999999 9",
                "9999999 99",
                "999999 999",
                "99999 9999",
                "9999 99999",
                "999 999999",
                "99 9999999",
                "9 99999999",
                " 999999999",
                NULL
            };
            p = invalid_puks;
            while (const char * puk = *p++) {
                bool result = OtpUtil::validateRecoveryPuk(std::string(puk));
                ccstAssertFalse(result, "PUK '%s' should not pass the test", puk);
            }
        }
        
        void testRecoveryCodeParser()
        {
            OtpComponents components;
            bool result;
            
            // valid sequences
            result = OtpUtil::parseRecoveryCode("BBBBB-BBBBB-BBBBB-BTA6Q", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "BBBBB-BBBBB-BBBBB-BTA6Q");
            
            result = OtpUtil::parseRecoveryCode("R:BBBBB-BBBBB-BBBBB-BTA6Q", components);
            ccstAssertTrue(result);
            ccstAssertEqual(components.activationCode, "BBBBB-BBBBB-BBBBB-BTA6Q");
            
            // invalid sequences
            result = OtpUtil::parseRecoveryCode("", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("#AB==", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("KLMNO-PQRST", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("EEEEE-EEEEE-EEEEE-E2OXA#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("OOOOO-OOOOO-OOOOO-OZH2Q#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("SSSSS-SSSSS-SSSSS-SX7IA#AB", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("UUUUU-UUUUU-UUUUU-UAFLQ#AB#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("WWWWW-WWWWW-WWWWW-WNR7A#ABA=#", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("XXXXX-XXXXX-XXXXX-X6RBQ#ABA-=", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("DDDDD-DDDDD-DDDDD-D6UKA#ABC=", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("EEEEE-EEEEE-EEEEE-E2OXA#AB==", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("R:DDDDD-DDDDD-DDDDD-D6UKA#ABC=", components);
            ccstAssertFalse(result);
            result = OtpUtil::parseRecoveryCode("R:EEEEE-EEEEE-EEEEE-E2OXA#AB==", components);
            ccstAssertFalse(result);
        }
        
        //////
        
        void niceCodeGenerator()
        {
            std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            for (char c: chars) {
                std::string nice_base(16, c);
                ByteArray nice_bytes = cc7::FromBase32String(nice_base, false);
                auto check_sum = cc7::ToBigEndian(utils::CRC16_Calculate(nice_bytes));
                nice_bytes.append(cc7::MakeRange(check_sum));
                auto nice_code = cc7::ToBase32String(nice_bytes, false);
                auto nice_final_code = nice_code.substr(0, 5) + "-" + nice_code.substr(5, 5) + "-" +
                                       nice_code.substr(10, 5) + "-" + nice_code.substr(15, 5);
                ccstMessage("Nice code: %s", nice_final_code.c_str());
            }
        }
    };
    
    CC7_CREATE_UNIT_TEST(pa2OtpUtilTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
