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
#include <cc7tests/detail/StringUtils.h>
#include "../PowerAuth/crypto/CryptoUtils.h"
#include "../PowerAuth/protocol/ProtocolUtils.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    extern TestDirectory g_pa2Files;
    
    class pa2ActivationStatusBlobTests : public UnitTest
    {
    public:
        pa2ActivationStatusBlobTests()
        {
            CC7_REGISTER_TEST_METHOD(testPublicKeyFingerprint)
            CC7_REGISTER_TEST_METHOD(testEncryptedStatusBlobData)
            CC7_REGISTER_TEST_METHOD(testByteCountersDistance)
        }
        
        void testPublicKeyFingerprint()
        {
            JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/activation-status-blob-iv.json");
            auto&& data = root.arrayAtPath("data");
            for (const JSONValue & item : data) {
                // Load data
                cc7::ByteArray transportKey  = item.dataFromBase64StringAtPath("input.transportKey");
                cc7::ByteArray challenge     = item.dataFromBase64StringAtPath("input.challenge");
                cc7::ByteArray nonce         = item.dataFromBase64StringAtPath("input.nonce");
                cc7::ByteArray expectedIV    = item.dataFromBase64StringAtPath("output.iv");
                cc7::ByteArray calculatedIV = protocol::DeriveIVForStatusBlobDecryption(challenge, nonce, transportKey);
                
                if (calculatedIV != expectedIV) {
                    ccstFailure("Doesn't match: Expected %s vs %s", expectedIV.hexString().c_str(), calculatedIV.hexString().c_str());
                    break;
                }
            }
        }
        
        void testEncryptedStatusBlobData()
        {
            JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/activation-status-blob-data.json");
            auto&& data = root.arrayAtPath("data");
            for (const JSONValue & item : data) {
                // Load input data
                cc7::ByteArray transportKey  = item.dataFromBase64StringAtPath("input.transportKey");
                cc7::ByteArray challenge     = item.dataFromBase64StringAtPath("input.challenge");
                cc7::ByteArray nonce         = item.dataFromBase64StringAtPath("input.nonce");
                cc7::ByteArray ctrData       = item.dataFromBase64StringAtPath("input.ctrData");
                cc7::ByteArray cStatusBlob   = item.dataFromBase64StringAtPath("input.encryptedStatusBlob");
                
                // Load expected values
                auto expActivationStatus    = item.stringAtPath("output.activationStatus");
                auto expCurrentVersion      = item.stringAtPath("output.currentVersion");
                auto expUpgradeVersion      = item.stringAtPath("output.upgradeVersion");
                auto expFailedAttempts      = item.stringAtPath("output.failedAttempts");
                auto expMaxFailedAttempts   = item.stringAtPath("output.maxFailedAttempts");
                auto expCtrLookAhead        = item.stringAtPath("output.ctrLookAhead");
                auto expCtrByte             = item.stringAtPath("output.ctrByte");
                auto expCtrDataHash         = item.stringAtPath("output.ctrDataHash");
                auto expCounterDistance     = item.stringAtPath("output.counterDistance");
                
                // Try to decrypt status
                ActivationStatus status;
                auto result = protocol::DecryptEncryptedStatusBlob(cStatusBlob, challenge, nonce, transportKey, status);
                ccstAssertEqual(EC_Ok, result);
                
                // Validate expected values
                ccstAssertEqual(expActivationStatus, std::to_string((int)status.state));
                ccstAssertEqual(expCurrentVersion, std::to_string((int)status.currentVersion));
                ccstAssertEqual(expUpgradeVersion, std::to_string((int)status.upgradeVersion));
                ccstAssertEqual(expFailedAttempts, std::to_string((int)status.failCount));
                ccstAssertEqual(expMaxFailedAttempts, std::to_string((int)status.maxFailCount));
                ccstAssertEqual(expCtrLookAhead, std::to_string((int)status.lookAheadCount));
                ccstAssertEqual(expCtrByte, std::to_string((int)status.ctrByte));
                ccstAssertEqual(expCtrDataHash, status.ctrDataHash.base64String());
                
                // Calculate distance between
                auto local_ctr_data = ctrData;
                int distance = protocol::CalculateHashCounterDistance(local_ctr_data, status.ctrDataHash, transportKey, status.lookAheadCount);
                ccstAssertEqual(expCounterDistance, std::to_string(distance));
            }
        }
        
        void testByteCountersDistance()
        {
            for (int CTR = 0; CTR < 10000; CTR++) {
                for (int expected_distance = -100; expected_distance <= 100; expected_distance++) {
                    int server_CTR = CTR;
                    int local_CTR = CTR + expected_distance;
                    if (local_CTR < 0) {
                        continue;   // don't need to repead the same test
                    }
                    int calculated_distance = protocol::CalculateDistanceBetweenByteCounters((cc7::byte)local_CTR, (cc7::byte)server_CTR);
                    ccstAssertEqual(expected_distance, calculated_distance);
                }
            }
        }
    };
    
    CC7_CREATE_UNIT_TEST(pa2ActivationStatusBlobTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
