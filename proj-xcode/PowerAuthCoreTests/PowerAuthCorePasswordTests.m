/*
 * Copyright 2022 Wultra s.r.o.
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

#include <XCTest/XCTest.h>

@import PowerAuthCore;

@interface PowerAuthCorePasswordTests : XCTestCase
@end

@implementation PowerAuthCorePasswordTests

#define DATA_BYTES(vn, ...) \
    const UInt8 vn##bytes[] = __VA_ARGS__; \
    NSData * vn = [NSData dataWithBytes:vn##bytes length:sizeof(vn##bytes)];

- (void) testImmutable
{
    PowerAuthCorePassword * p1 = [PowerAuthCorePassword passwordWithString:@"HelloWorld"];
    XCTAssertEqual(10, p1.length);
    XCTAssertEqualObjects(@"HelloWorld", [self extractStringFromPassword:p1]);
    
    PowerAuthCorePassword * p2 = [PowerAuthCorePassword passwordWithString:@"HelloWorld"];
    XCTAssertTrue([p1 isEqualToPassword:p2]);
    XCTAssertEqualObjects(p1, p2);
    
    DATA_BYTES(p3data, { 1, 2, 3, 4, 5, 6, 7 });
    PowerAuthCorePassword * p3 = [PowerAuthCorePassword passwordWithData:p3data];
    XCTAssertEqual(7, p3.length);
    XCTAssertEqualObjects([p3data copy], [self extractBytesFromPassword:p3]);
}

- (void) testMutableNumbers
{
    PowerAuthCoreMutablePassword * p1 = [PowerAuthCoreMutablePassword mutablePassword];
    XCTAssertEqual(0, p1.length);
    
    XCTAssertTrue([p1 addCharacter:1]);
    XCTAssertTrue([p1 insertCharacter:3 atIndex:1]);
    XCTAssertTrue([p1 insertCharacter:0 atIndex:0]);
    XCTAssertTrue([p1 insertCharacter:2 atIndex:2]);
    XCTAssertTrue([p1 addCharacter:4]);
    XCTAssertEqual(5, p1.length);
    
    DATA_BYTES(expectedBytes1, { 0, 1, 2, 3, 4});
    XCTAssertEqualObjects([PowerAuthCorePassword passwordWithData:expectedBytes1], p1);
    
    XCTAssertTrue([p1 removeCharacterAtIndex:0]);
    DATA_BYTES(expectedBytes2, { 1, 2, 3, 4});
    XCTAssertEqualObjects([PowerAuthCorePassword passwordWithData:expectedBytes2], p1);
    
    XCTAssertTrue([p1 removeCharacterAtIndex:1]);
    DATA_BYTES(expectedBytes3, { 1, 3, 4});
    XCTAssertEqualObjects([PowerAuthCorePassword passwordWithData:expectedBytes3], p1);
    
    XCTAssertTrue([p1 removeCharacterAtIndex:2]);
    DATA_BYTES(expectedBytes4, { 1, 3 });
    XCTAssertEqualObjects([PowerAuthCorePassword passwordWithData:expectedBytes4], p1);
    
    XCTAssertTrue([p1 removeLastCharacter]);
    XCTAssertTrue([p1 removeLastCharacter]);
    
    // Out of range access
    XCTAssertFalse([p1 removeLastCharacter]);
    XCTAssertFalse([p1 removeCharacterAtIndex:0]);
    XCTAssertFalse([p1 removeCharacterAtIndex:1]);
    XCTAssertFalse([p1 insertCharacter:11 atIndex:1]);
    
    XCTAssertEqual(0, p1.length);
    XCTAssertTrue([p1 addCharacter:5]);
    XCTAssertEqual(1, p1.length);
    
    [p1 clear];
    XCTAssertEqual(0, p1.length);
}

- (void) testMutableUnicode
{
    PowerAuthCoreMutablePassword * p1 = [PowerAuthCoreMutablePassword mutablePassword];
    XCTAssertEqual(0, p1.length);
    
    XCTAssertTrue([p1 addCharacter:'e']);
    XCTAssertTrue([p1 addCharacter:'l']);
    XCTAssertTrue([p1 insertCharacter:'l' atIndex:1]);
    XCTAssertTrue([p1 insertCharacter:'o' atIndex:3]);
    XCTAssertTrue([p1 addCharacter:'W']);
    XCTAssertTrue([p1 addCharacter:'0']);
    XCTAssertTrue([p1 addCharacter:'r']);
    XCTAssertTrue([p1 addCharacter:'l']);
    XCTAssertTrue([p1 addCharacter:'d']);
    XCTAssertTrue([p1 insertCharacter:0x397 atIndex:0]);
    
    XCTAssertEqual(10, p1.length);
    XCTAssertEqual(11, [self extractBytesFromPassword:p1].length);
    XCTAssertEqualObjects(@"ΗelloW0rld", [self extractStringFromPassword:p1]);
    
    XCTAssertTrue([p1 removeCharacterAtIndex:0]);
    XCTAssertEqualObjects(@"elloW0rld", [self extractStringFromPassword:p1]);
    XCTAssertTrue([p1 removeLastCharacter]);
    XCTAssertEqualObjects(@"elloW0rl", [self extractStringFromPassword:p1]);
    XCTAssertTrue([p1 insertCharacter:0x206 atIndex:1]);
    XCTAssertEqualObjects(@"eȆlloW0rl", [self extractStringFromPassword:p1]);
    XCTAssertEqual(9, p1.length);
    XCTAssertTrue([p1 removeCharacterAtIndex:5]);
    XCTAssertEqualObjects(@"eȆllo0rl", [self extractStringFromPassword:p1]);
    XCTAssertTrue([p1 removeCharacterAtIndex:1]);
    XCTAssertEqualObjects(@"ello0rl", [self extractStringFromPassword:p1]);
}

- (void) testPasswordEqual
{
    DATA_BYTES(p2data, { 'f', 'i', 'x', 'e', 'd' });
    PowerAuthCorePassword * p1 = [PowerAuthCorePassword passwordWithString:@"fixed"];
    PowerAuthCorePassword * p2 = [PowerAuthCorePassword passwordWithData:p2data];
    PowerAuthCoreMutablePassword * p3 = [PowerAuthCoreMutablePassword mutablePassword];
    [p3 addCharacter:'f'];
    [p3 addCharacter:'i'];
    [p3 addCharacter:'x'];
    [p3 addCharacter:'e'];
    [p3 addCharacter:'d'];
    XCTAssertEqualObjects(p1, p1);
    XCTAssertEqualObjects(p2, p2);
    XCTAssertEqualObjects(p3, p3);
    XCTAssertEqualObjects(p1, p2);
    XCTAssertEqualObjects(p1, p3);
    XCTAssertEqualObjects(p2, p3);
}

- (void) testPasswordNotEqual
{
    PowerAuthCorePassword * p1 = [PowerAuthCorePassword passwordWithString:@"fixed"];
    PowerAuthCorePassword * p2 = [PowerAuthCorePassword passwordWithString:@"strin"];
    PowerAuthCorePassword * p3 = [PowerAuthCorePassword passwordWithString:@"string"];
    PowerAuthCorePassword * p4 = [PowerAuthCorePassword passwordWithString:@"stri"];
    PowerAuthCorePassword * p5 = [PowerAuthCoreMutablePassword mutablePassword];
    XCTAssertFalse([p1 isEqualToPassword:p2]);
    XCTAssertFalse([p1 isEqualToPassword:p3]);
    XCTAssertFalse([p1 isEqualToPassword:p4]);
    XCTAssertFalse([p1 isEqualToPassword:p5]);
    XCTAssertFalse([p2 isEqualToPassword:p3]);
    XCTAssertFalse([p2 isEqualToPassword:p4]);
    XCTAssertFalse([p2 isEqualToPassword:p5]);
    XCTAssertFalse([p3 isEqualToPassword:p4]);
    XCTAssertFalse([p3 isEqualToPassword:p5]);
    XCTAssertFalse([p4 isEqualToPassword:p5]);
    XCTAssertNotEqualObjects(@"fixed", p1);
    XCTAssertNotEqualObjects(p1, @"fixed");
}

- (NSString*) extractStringFromPassword:(PowerAuthCorePassword*)password
{
    __block NSString * stringPassword = nil;
    [password validatePasswordComplexity:^NSInteger(const UInt8 * _Nonnull passphrase, NSUInteger length) {
        stringPassword = [[NSString alloc] initWithBytes:passphrase length:length encoding:NSUTF8StringEncoding];
        return 0;
    }];
    return stringPassword;
}

- (NSData*) extractBytesFromPassword:(PowerAuthCorePassword*)password
{
    __block NSData * passwordData = nil;
    [password validatePasswordComplexity:^NSInteger(const UInt8 * _Nonnull passphrase, NSUInteger length) {
        passwordData = [NSData dataWithBytes:passphrase length:length];
        return 0;
    }];
    return passwordData;
}

@end
