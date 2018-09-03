/*
 * Copyright 2016-2017 Wultra s.r.o.
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
			CC7_REGISTER_TEST_METHOD(testCodeValidation)
			CC7_REGISTER_TEST_METHOD(testCharValidation)
			CC7_REGISTER_TEST_METHOD(testCharAutocorrection)
			CC7_REGISTER_TEST_METHOD(testParser)
		}
		
		
		// unit tests

		void testCodeValidation()
		{
			const char * valid_codes[] = {
				"ABCDE-FGHIJ-KLMNO-PQRST",
				"KLMNO-PQRST-UVWXY-Z2345",
				"67AAA-BBBCC-DDEEF-GGHHI",
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
		
		
		void testParser()
		{
			OtpComponents components;
			bool result;
			
			// valid sequences
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST", components);
			ccstAssertTrue(result);
			ccstAssertEqual(components.activationOtp, "KLMNO-PQRST");
			ccstAssertEqual(components.activationIdShort, "ABCDE-FGHIJ");
			ccstAssertEqual(components.activationSignature, "");
			ccstAssertFalse(components.hasSignature());
			
			result = OtpUtil::parseActivationCode("67AAA-BBBCC-DDEEF-GGHHI#ABCD", components);
			ccstAssertTrue(result);
			ccstAssertEqual(components.activationOtp, "DDEEF-GGHHI");
			ccstAssertEqual(components.activationIdShort, "67AAA-BBBCC");
			ccstAssertEqual(components.activationSignature, "ABCD");
			ccstAssertTrue(components.hasSignature());
			
			result = OtpUtil::parseActivationCode("67AAA-BBBCC-DDEEF-GGHHI#ABC=", components);
			ccstAssertTrue(result);
			ccstAssertEqual(components.activationOtp, "DDEEF-GGHHI");
			ccstAssertEqual(components.activationIdShort, "67AAA-BBBCC");
			ccstAssertEqual(components.activationSignature, "ABC=");
			ccstAssertTrue(components.hasSignature());

			result = OtpUtil::parseActivationCode("67AAA-BBBCC-DDEEF-GGHHI#AB==", components);
			ccstAssertTrue(result);
			ccstAssertEqual(components.activationOtp, "DDEEF-GGHHI");
			ccstAssertEqual(components.activationIdShort, "67AAA-BBBCC");
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
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#", components);
			ccstAssertFalse(result);
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#", components);
			ccstAssertFalse(result);
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#AB", components);
			ccstAssertFalse(result);
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#AB#", components);
			ccstAssertFalse(result);
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#ABA=#", components);
			ccstAssertFalse(result);
			result = OtpUtil::parseActivationCode("ABCDE-FGHIJ-KLMNO-PQRST#ABA-=", components);
			ccstAssertFalse(result);
		}

	};
	
	CC7_CREATE_UNIT_TEST(pa2OtpUtilTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
