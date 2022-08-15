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
#include <PowerAuth/Password.h>

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2PasswordTests : public UnitTest
    {
    public:
        
        pa2PasswordTests()
        {
            CC7_REGISTER_TEST_METHOD(testImmutable)
            CC7_REGISTER_TEST_METHOD(testMutableNumbers)
            CC7_REGISTER_TEST_METHOD(testMutableUnicode)
        }
        
        // unit tests

        void testImmutable()
        {
            Password p1;
            p1.initAsImmutable(cc7::MakeRange("HelloWorld"));
            ccstAssertFalse(p1.isMutable());
            ccstAssertEqual(p1.length(), 10);
            ccstAssertEqual(p1.passwordData().byteRange(), cc7::MakeRange("HelloWorld"));
            
            Password p2;
            p2.initAsImmutable(cc7::MakeRange("HelloWorld"));
            ccstAssertTrue(p1.isEqualToPassword(p2));
            
            // reinitialization
            p1.initAsImmutable(cc7::ByteArray{ 1, 2, 3, 4, 5, 6, 7 });
            ccstAssertEqual(p1.length(), 7);
            ccstAssertFalse(p1.isEqualToPassword(p2));
            ccstAssertEqual(p1.passwordData(), (cc7::ByteArray{ 1, 2, 3, 4, 5, 6, 7 }));
            
            // reinit to mutable
            p1.initAsMutable();
            ccstAssertEqual(p1.length(), 0);
            ccstAssertTrue(p1.isMutable());
            
            // back to immutable
            p1.initAsImmutable(cc7::ByteArray{ 1, 2, 3, 4, 5, 6, 7 });
            ccstAssertEqual(p1.length(), 7);
            ccstAssertFalse(p1.isEqualToPassword(p2));
            ccstAssertEqual(p1.passwordData(), (cc7::ByteArray{ 1, 2, 3, 4, 5, 6, 7 }));
            
            // Immutable doesn't allow modifications
            bool result = p1.removeLastCharacter();
            ccstAssertFalse(result);
            result = p1.removeCharacter(0);
            ccstAssertFalse(result);
            result = p1.addCharacter(11);
            ccstAssertFalse(result);
            result = p1.insertCharacter(12, 0);
            ccstAssertFalse(result);
        }
        
        void testMutableNumbers()
        {
            bool result;
            Password p1;
            p1.initAsMutable();
            
            result = p1.addCharacter(0);
            ccstAssertTrue(result);
            result = p1.addCharacter(1);
            ccstAssertTrue(result);
            result = p1.insertCharacter(3, 2);
            ccstAssertTrue(result);
            result = p1.insertCharacter(2, 2);
            ccstAssertTrue(result);
            ccstAssertEqual(p1.length(), 4);
            ccstAssertEqual(p1.passwordData(), cc7::ByteArray({0, 1, 2, 3}));
            
            result = p1.removeLastCharacter();
            ccstAssertTrue(result);
            result = p1.removeLastCharacter();
            ccstAssertTrue(result);
            result = p1.removeLastCharacter();
            ccstAssertTrue(result);
            result = p1.removeLastCharacter();
            ccstAssertTrue(result);
            
            // out of range access
            result = p1.removeLastCharacter();
            ccstAssertFalse(result);
            result = p1.removeCharacter(0);
            ccstAssertFalse(result);
            result = p1.removeCharacter(1);
            ccstAssertFalse(result);
            result = p1.insertCharacter(11, 1);
            ccstAssertFalse(result);
            ccstAssertEqual(0, p1.length());
        }

        void testMutableUnicode()
        {
            bool result;
            
            Password p1;
            p1.initAsMutable();
            
            result = p1.addCharacter('e');
            ccstAssertTrue(result);
            result = p1.addCharacter('l');
            ccstAssertTrue(result);
            result = p1.addCharacter('l');
            ccstAssertTrue(result);
            result = p1.addCharacter('o');
            ccstAssertTrue(result);
            result = p1.addCharacter('W');
            ccstAssertTrue(result);
            result = p1.addCharacter('o');
            ccstAssertTrue(result);
            result = p1.addCharacter('r');
            ccstAssertTrue(result);
            result = p1.addCharacter('l');
            ccstAssertTrue(result);
            result = p1.insertCharacter('d', p1.length());
            ccstAssertTrue(result);
            result = p1.insertCharacter(0x397, 0);
            ccstAssertTrue(result);
            ccstAssertEqual(p1.length(), 10);
            ccstAssertEqual(p1.passwordData().size(), 11);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"ΗelloWorld"));
            
            result = p1.removeCharacter(0);
            ccstAssertTrue(result);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"elloWorld"));
            ccstAssertEqual(p1.length(), 9);
            result = p1.removeLastCharacter();
            ccstAssertTrue(result);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"elloWorl"));
            ccstAssertEqual(p1.length(), 8);
            result = p1.insertCharacter(0x206, 1);
            ccstAssertTrue(result);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"eȆlloWorl"));
            ccstAssertEqual(p1.length(), 9);
            result = p1.removeCharacter(5);
            ccstAssertTrue(result);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"eȆlloorl"));
            ccstAssertEqual(p1.length(), 8);
            result = p1.removeCharacter(1);
            ccstAssertTrue(result);
            ccstAssertTrue(p1.passwordData() == cc7::MakeRange(u8"elloorl"));
            ccstAssertEqual(p1.length(), 7);
        }
        
    };
    
    CC7_CREATE_UNIT_TEST(pa2PasswordTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
