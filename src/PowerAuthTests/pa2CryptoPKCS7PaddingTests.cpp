/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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
#include <cc7/HexString.h>
#include "crypto/CryptoUtils.h"
#include "crypto/PKCS7Padding.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2CryptoPKCS7PaddingTests : public UnitTest
	{
	public:
		
		pa2CryptoPKCS7PaddingTests()
		{
			CC7_REGISTER_TEST_METHOD(testPadding)
			CC7_REGISTER_TEST_METHOD(testWrongPadding)
		}
		
		// unit tests
		
		void testPadding()
		{
			const size_t paddings[4] =
			{
				16, 32, 64, 128
			};
			
			for (size_t pi = 0; pi < sizeof(paddings)/sizeof(size_t); pi++) {
				const size_t padding = paddings[pi];
				
				for (size_t n = 0; n < 259; n++) {
					// Get a random stuff
					cc7::ByteArray data  = crypto::GetRandomData(n);
					ccstAssertTrue(data.size() == n, "Random generator failed");
					// Make copy of data, just to be sure that padding doesn't modify original data
					cc7::ByteArray padded = crypto::PKCS7_GetPaddedData(data, padding);
					
					// Calculate how many bytes we need to add. The value is also padding byte itself.
					size_t expected_additional_bytes = padding - (data.size() & (padding - 1));
					if (!expected_additional_bytes) {
						// Make sure that there's always nonzero padding.
						expected_additional_bytes = padding;
					}
					if (n == 0) {
						// Covers empty data. The testing loop will not run due to zero size and therefore
						// we have to perform one special test here.
						ccstAssertTrue(expected_additional_bytes == padded.size());
					} else {
						// Otherwise we can perform modulo test to zero. You can see that this test
						// produces false positive result for empty data.
						ccstAssertTrue(padded.size() % 16 == 0);
					}
					for (size_t i = 0; i < padded.size(); i++) {
						if (i < n) {
							// content must be equal to original data
							if (data[i] != padded[i]) {
								ccstFailure("Corrupted original data at index %d. Data size %d", (int)i, (int)n);
								return;
							}
						} else {
							if (padded[i] != expected_additional_bytes) {
								ccstFailure("Wrong padding value at index %d. Data size %d", (int)i, (int)n);
								return;
							}
						}
					}
					// Unpad previously padded data and compare result.
					cc7::ByteArray unpadded = padded;
					bool success = crypto::PKCS7_ValidateAndUpdateData(unpadded, padding);
					ccstAssertTrue(success);
					ccstAssertEqual(unpadded, data);
				}
			}
		}
		
		void testWrongPadding()
		{
			const char * badpads[] = {
				"",
				"00",
				"000102030405060708090A0B0C0D0E",
				"000102030405060708090A0B0C0D0E0FBB",
				"000102030405060708090A0B0C0D0E0F",
				"000102030405060708090A0B0C0D0E11",
				"000102030405060708090A0B03040404",
				"11101010101010101010101010101010",
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E",
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0FBB",
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F",
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E21",
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E2111101010101010101010101010101010",
				
				NULL
			};
			
			const char ** testdata = badpads;
			while (*testdata) {
				const char * teststr = *(testdata++);
				cc7::ByteArray td = cc7::FromHexString(teststr);
				ccstAssertTrue(td.size() * 2 == strlen(teststr));
				//ccstMessage("Checking %s", teststr);
				size_t result = crypto::PKCS7_Validate(td, 16);
				ccstAssertTrue(result == 0, "Data (%d) %s should not pass in validation", (int)td.size(), teststr);
			}
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2CryptoPKCS7PaddingTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
