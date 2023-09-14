/*
 * Copyright 2023 Wultra s.r.o.
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
#include <PowerAuth/ByteUtils.h>
#include "crypto/PRNG.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;
using namespace io::getlime::powerAuth::utils;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2ByteUtilsTests : public UnitTest
    {
    public:
        
        pa2ByteUtilsTests()
        {
            CC7_REGISTER_TEST_METHOD(testConcat)
            CC7_REGISTER_TEST_METHOD(testJoin)
        }
        
        void testConcat()
        {
            auto data = utils::ByteUtils_Concat({});
            ccstAssertTrue(data.empty());
            data = utils::ByteUtils_Concat({
                cc7::MakeRange("hello"),
                cc7::MakeRange(cc7::byte(32)),
                cc7::MakeRange("world!")
            });
            auto expected = "hello world!";
            ccstAssertEqual(cc7::MakeRange(expected), data);
            data = utils::ByteUtils_Concat({
                cc7::ByteRange(),
                cc7::ByteRange(),
                cc7::ByteRange(),
                cc7::ByteRange()
            });
            ccstAssertTrue(data.empty());
        }
        
        void testJoin()
        {
            auto data = utils::ByteUtils_Join({});
            ccstAssertTrue(data.empty());
            data = utils::ByteUtils_Join({
                cc7::ByteRange()
            });
            ccstAssertEqual(cc7::MakeRange(cc7::U32(0)), data);
            data = utils::ByteUtils_Join({
                cc7::MakeRange("hello"),
                cc7::MakeRange(cc7::byte(32)),
                cc7::MakeRange("world!"),
                cc7::ByteRange()
            });
            cc7::byte expected[] = {
                0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o',
                0, 0, 0, 1, ' ',
                0, 0, 0, 6, 'w', 'o', 'r', 'l', 'd', '!',
                0, 0, 0, 0
            };
            ccstAssertEqual(cc7::MakeRange(expected), data);
            
            auto r1 = crypto::GetRandomData(0x00102);
            auto r2 = crypto::GetRandomData(0x10002);
            data = utils::ByteUtils_Join({r1, r2});
            auto expected_bytes = cc7::ByteArray();
            expected_bytes.append({ 0, 0, 1, 2});
            expected_bytes.append(r1);
            expected_bytes.append({ 0, 1, 0, 2});
            expected_bytes.append(r2);
            ccstAssertEqual(expected_bytes, data);
        }
    };

    CC7_CREATE_UNIT_TEST(pa2ByteUtilsTests, "pa2")

} // io::getlime::powerAuthTests
} // io::getlime
} // io
