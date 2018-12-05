/*
 * Copyright 2018 Wultra s.r.o.
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
#include <cc7tests/detail/StringUtils.h>
#include "../PowerAuth/utils/CRC16.h"
#include "../PowerAuth/utils/DataWriter.h"
#include "../PowerAuth/crypto/CryptoUtils.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2CRC16Tests : public UnitTest
	{
	public:
		
		pa2CRC16Tests()
		{
			CC7_REGISTER_TEST_METHOD(testCalculate)
			CC7_REGISTER_TEST_METHOD(testValidate)
		}
		
		// unit tests
		
		void testCalculate()
		{
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("iV6jP5Xr0z")) == 0xC6EB);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("dD5HnVp68n")) == 0x2762);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("Fuu5G0DUJR")) == 0x4FE7);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("iPeHJFjSCh")) == 0x337B);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("vBS8tFjAOx")) == 0xD8CC);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("iJA6cuvi4q")) == 0xE597);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("MeIWdZggy0")) == 0xE53B);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("The quick brown fox jumps over the lazy dog.")) == 0x843D);
			ccstAssertTrue(utils::CRC16_Calculate(cc7::MakeRange("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
																 "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
																 "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo "
																 "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse "
																 "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat "
																 "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")) == 0xA8E2);
		}
		
		void testValidate()
		{
			for (int i = 0; i < 1000; i++) {
				size_t random_count = arc4random_uniform(128);
				utils::DataWriter writer;
				writer.writeMemory(crypto::GetRandomData(random_count));
				auto crc = utils::CRC16_Calculate(writer.serializedData());
				writer.writeU16(crc);
				// Now validate the checksum
				ccstAssertTrue(utils::CRC16_Validate(writer.serializedData()));
			}
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2CRC16Tests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
