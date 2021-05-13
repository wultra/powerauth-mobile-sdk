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
	class pa2CryptoHMACTests : public UnitTest
	{
	public:
		
		pa2CryptoHMACTests()
		{
			CC7_REGISTER_TEST_METHOD(testPBKDF2_HMAC_SHA1)
			CC7_REGISTER_TEST_METHOD(testHMAC_SHA256)
		}
		
		// unit tests
		
		struct TestData1
		{
			const char * password;
			const char * salt;
			int          iterations;
			int          dklen;
			uint8_t      expected[25];
			size_t       password_len;
			size_t       salt_len;
		};

		void testPBKDF2_HMAC_SHA1()
		{
			static const TestData1 vectors[] =
			{
				{
					"password", "salt", 1, 20,
					{
						0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5,
						0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
					}
				},
				{
					"password", "salt", 2, 20,
					{
						0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9,
						0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
					}
				},
				{
					"password", "salt", 4096, 20,
					{
						0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49,
						0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
					}
				},
				{
					"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
					{
						0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
						0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
						0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
						0x38
					}
				},
				{
					"pass\0word", "sa\0lt", 4096, 16,
					{
						0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
						0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
					},
					9, 5, // optional, cusotm len for pass & salt
				},
				{
					nullptr, nullptr, 0
				}
			};
			
			const TestData1 * td = vectors;
			int iteration = 0;
			while (td->password) {
				size_t pass_len = td->password_len ? td->password_len : strlen(td->password);
				size_t salt_len = td->salt_len     ? td->salt_len     : strlen(td->salt);
				const uint8_t * exp_ptr = td->expected;
				cc7::ByteArray pass		(td->password, td->password + pass_len);
				cc7::ByteArray salt		(td->salt,     td->salt     + salt_len);
				cc7::ByteArray expected	(exp_ptr,	   exp_ptr      + td->dklen);
				
				cc7::ByteArray calculated = crypto::PBKDF2_HMAC_SHA1(pass, salt, td->iterations, td->dklen);
				ccstAssertTrue(calculated.size() == td->dklen);
				ccstAssertTrue(expected == calculated, "Failed at iteration %d", iteration);
				
				iteration++;
				td++;
			}
		}
		
		struct TestData2
		{
			const char * key;
			const char * data;
			const char * hmac;
		};
		
		void testHMAC_SHA256()
		{
			static const TestData2 vectors[] =
			{
				{
					"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
					"4869205468657265",
					"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
				},
				{
					"4a656665",
					"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
					"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
				},
				{
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
					"dddddddddddddddddddddddddddddddddddd",
					"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
				},
				{
					"0102030405060708090a0b0c0d0e0f10111213141516171819",
					"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
					"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
					"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
				},
				{
					"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
					"546573742057697468205472756e636174696f6e",
					"a3b6167473100ee06e0c796c2955552b"
				},
				{
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
					"65204b6579202d2048617368204b6579204669727374",
					"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
				},
				{
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"5468697320697320612074657374207573696e672061206c6172676572207468"
					"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
					"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
					"647320746f20626520686173686564206265666f7265206265696e6720757365"
					"642062792074686520484d414320616c676f726974686d2e",
					"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
				},
				
				{ nullptr, nullptr, nullptr }
			};
			const TestData2 *td = vectors;
			while (td->key) {
				cc7::ByteArray key  = cc7::FromHexString(td->key);
				cc7::ByteArray data = cc7::FromHexString(td->data);
				cc7::ByteArray exp  = cc7::FromHexString(td->hmac);
				cc7::ByteArray hmac = crypto::HMAC_SHA256(data, key, exp.size());
				bool equal = hmac == exp;
				ccstAssertTrue(equal);
				if (!equal) {
					ccstMessage("exp %s", exp.hexString().c_str());
					ccstMessage("our %s", hmac.hexString().c_str());
				}
				td++;
			}
		}

	};
	
	CC7_CREATE_UNIT_TEST(pa2CryptoHMACTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
