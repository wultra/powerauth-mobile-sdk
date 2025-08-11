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

#include <PowerAuthTests/PowerAuthTestsList.h>

using namespace cc7;

namespace powerAuthTests {

cc7::tests::UnitTestCreationInfoList GetPowerAuthTestCreationInfoList()
{
    cc7::tests::UnitTestCreationInfoList list;
    
    // High level objects
    CC7_ADD_UNIT_TEST(ConfigurationTests, list);
    CC7_ADD_UNIT_TEST(PasswordTests, list);
    CC7_ADD_UNIT_TEST(CredentialsTests, list);
    CC7_ADD_UNIT_TEST(TimeServiceTests, list);
    CC7_ADD_UNIT_TEST(pa2OtpUtilTests, list);
    
    // Internal objets
    CC7_ADD_UNIT_TEST(RequestBuilderTests, list);
    
    // Crypto tests
    // v4
    CC7_ADD_UNIT_TEST(PowerAuthKDFTests, list);
    CC7_ADD_UNIT_TEST(PowerAuthAEADTests, list);
    CC7_ADD_UNIT_TEST(SharedSecretTests, list);
    CC7_ADD_UNIT_TEST(HybridKeyPairTests, list);
    CC7_ADD_UNIT_TEST(KeyProviderV4Tests, list);
    CC7_ADD_UNIT_TEST(AuthCodeV4, list);
    // v3
    CC7_ADD_UNIT_TEST(KeyProviderV3Tests, list);
    
    // legacy
    CC7_ADD_UNIT_TEST(pa2CryptoAESTests, list);
    CC7_ADD_UNIT_TEST(pa2CryptoHMACTests, list);
    CC7_ADD_UNIT_TEST(pa2CryptoECDHKDFTests, list);
    CC7_ADD_UNIT_TEST(pa2CryptoECCTests, list);
    
    // Protocol tests
    CC7_ADD_UNIT_TEST(ClientEncryptorTests, list);
    
    // Utils
    CC7_ADD_UNIT_TEST(pa2ByteUtilsTests, list);
    CC7_ADD_UNIT_TEST(pa2CRC16Tests, list);

    return list;
}
    
} // namespace powerAuthTests
