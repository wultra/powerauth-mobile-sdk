/*
 * Copyright 2016-2019 Wultra s.r.o.
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

#include <PowerAuthTests/PowerAuthTestsList.h>

using namespace cc7;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	cc7::tests::UnitTestCreationInfoList GetPowerAuthTestCreationInfoList()
	{
		cc7::tests::UnitTestCreationInfoList list;
		
		// High level objects
		CC7_ADD_UNIT_TEST(pa2DataWriterReaderTests, list);
		CC7_ADD_UNIT_TEST(pa2SessionTests, list);
		CC7_ADD_UNIT_TEST(pa2PasswordTests, list);
		CC7_ADD_UNIT_TEST(pa2OtpUtilTests, list);
		CC7_ADD_UNIT_TEST(pa2ECIESTests, list);
		
		// Crypto tests
		CC7_ADD_UNIT_TEST(pa2CryptoPKCS7PaddingTests, list);
		CC7_ADD_UNIT_TEST(pa2CryptoAESTests, list);
		CC7_ADD_UNIT_TEST(pa2CryptoHMACTests, list);
		CC7_ADD_UNIT_TEST(pa2CryptoECDHKDFTests, list);
		
		// Protocol tests
		CC7_ADD_UNIT_TEST(pa2ProtocolUtilsTests, list);
		CC7_ADD_UNIT_TEST(pa2RecoveryCodeTests, list);
		CC7_ADD_UNIT_TEST(pa2URLEncodingTests, list);
		CC7_ADD_UNIT_TEST(pa2SignatureKeysDerivationTest, list);
		CC7_ADD_UNIT_TEST(pa2MasterSecretKeyComputation, list);
		CC7_ADD_UNIT_TEST(pa2SignatureCalculationTests, list);
		CC7_ADD_UNIT_TEST(pa2PublicKeyFingerprintTests, list);
		CC7_ADD_UNIT_TEST(pa2ActivationStatusBlobTests, list);
		
		// Misc
		CC7_ADD_UNIT_TEST(pa2CRC16Tests, list);

		return list;
	}
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
