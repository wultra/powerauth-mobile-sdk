/*
 * Copyright 2024 Wultra s.r.o.
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

#import <XCTest/XCTest.h>
#import <PowerAuth2/PowerAuth2.h>
#import <PowerAuthCore/PowerAuthCore.h>

#import "PA2ObjectSerialization.h"
#import "PA2PrivateMacros.h"

@interface TestJwtObject : NSObject <PA2Encodable, PA2Decodable>
@property (nonatomic, strong) NSString * text;
@end

@implementation TestJwtObject
- (NSDictionary<NSString *,NSObject *> *)toDictionary
{
    return _text ? @{@"text": _text} : @{};
}
- (instancetype)initWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
    self = [super init];
    if (self) {
        _text = PA2ObjectAs(dictionary[@"text"], NSString);
    }
    return self;
}
@end

@interface PA2ObjectSerializationTests : XCTestCase
@end

@implementation PA2ObjectSerializationTests

- (void) testJwtSerialization
{
    TestJwtObject * data = (TestJwtObject*)[PA2ObjectSerialization deserializeJwtObject:@"eyJ0ZXh0Ijoixb7DtMW-w6QifQ" forClass:[TestJwtObject class] error:nil];
    XCTAssertTrue([data.text isEqualToString:@"žôžä"]);
    NSString * serializedData = [PA2ObjectSerialization serializeJwtObject:data];
    XCTAssertTrue([@"eyJ0ZXh0Ijoixb7DtMW-w6QifQ" isEqualToString:serializedData]);
    data = (TestJwtObject*)[PA2ObjectSerialization deserializeJwtObject:@"eyJ0ZXh0Ijoi8J-SqT8_In0" forClass:[TestJwtObject class] error:nil];
    XCTAssertTrue([data.text isEqualToString:@"💩??"]);
    serializedData = [PA2ObjectSerialization serializeJwtObject:data];
    XCTAssertTrue([@"eyJ0ZXh0Ijoi8J-SqT8_In0" isEqualToString:serializedData]);
}

- (void) testJwtDataConversion
{
    for (NSUInteger i = 0; i < 1000; i++) {
        NSUInteger len = arc4random_uniform(129);
        NSData * input = [PowerAuthCoreCryptoUtils randomBytes:len];
        NSString * inputB64url = [input jwtEncodedString];
        NSData * output = [[NSData alloc] initWithJwtEncodedString:inputB64url];
        XCTAssertEqualObjects(input, output);
    }
}

@end
