/*
 * Copyright 2019 Wultra s.r.o.
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
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"
#include "protocol/PrivateTypes.h"
#include "crypto/CryptoUtils.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2RecoveryCodeTests : public UnitTest
	{
	public:
		
		pa2RecoveryCodeTests()
		{
			CC7_REGISTER_TEST_METHOD(testGoodRecoveryData)
			CC7_REGISTER_TEST_METHOD(testBadRecoveryData)
		}
		
		// unit tests
		
		void testGoodRecoveryData()
		{
			RecoveryData rd;
			
			ccstAssertTrue(protocol::ValidateRecoveryData(rd));
			
			rd.recoveryCode = "VVVVV-VVVVV-VVVVV-VTFVA";
			rd.puk = "1111122222";
			
			ccstAssertTrue(protocol::ValidateRecoveryData(rd));
		}
		
		void testBadRecoveryData()
		{
			static struct TestData {
				const char * recovery_code;
				const char * puk;
			} bad_data[] = {
				{ "VVVVV-VVVVV-VVVVV-VTFVA", "" },
				{ "", "111112222" },
				{ "VVVVV-VVVVV-VVVVV-VTFVA", "111112222" },
				{ "VVVVV-VVVVV-VVVVV-VTFVA", "11111222233" },
				{ "VVVVV-VVVVV-VVVVV-VTFVA", "11111A2223" },
				{ "VVVVV-VVVVV-VVVVV-VTFVA", "11111 2223" },
				{ "VAVVV-VVVVV-VVVVV-VTFVA", "1111122222" },
				{ nullptr, nullptr }
			};
			
			const TestData * td = bad_data;
			while (td->recovery_code && td->puk) {
				RecoveryData rd;
				rd.recoveryCode = td->recovery_code;
				rd.puk = td->puk;
				
				td++;
			}
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2RecoveryCodeTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
