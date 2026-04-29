/*
 * Copyright 2025 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCore.h>

@interface NSData (PA_immutable)
- (NSData*) immutableCopy;
@end

@interface PowerAuthCoreDataTests : XCTestCase
@end

@implementation PowerAuthCoreDataTests

- (void) testCoreDataRelease
{
    NSData * data16_1 = [PowerAuthCoreCryptoUtils randomBytes:16];
    NSData * zero_data = [NSData data];
    
    NSData * capturedData = nil;
    @autoreleasepool {
        PowerAuthCoreData * coreData = [[PowerAuthCoreData alloc] initWithData:data16_1];
        capturedData = coreData.sensitiveData;
        XCTAssertNotEqual(data16_1, capturedData);
        XCTAssertEqualObjects(data16_1, coreData.sensitiveData);
    }
    // Leaving block above, coreData should destroy content of the data.
    XCTAssertNotEqualObjects(data16_1, capturedData);
    XCTAssertEqualObjects(zero_data, capturedData);
}

- (void) testCoreDataInitAndClear
{
    NSData * data16_ref = [PowerAuthCoreCryptoUtils randomBytes:16];
    NSData * data24_ref = [PowerAuthCoreCryptoUtils randomBytes:24];
    
    NSData * data16_imm = [data16_ref immutableCopy];
    NSData * data24_imm = [data24_ref immutableCopy];
    NSData * data16_mut = [data16_ref mutableCopy];
    NSData * data24_mut = [data24_ref mutableCopy];

    NSData * zero16 = [self zeroBytes:16 mutable:NO];
    NSData * zero24 = [self zeroBytes:24 mutable:NO];
    
    PowerAuthCoreData * coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:data16_imm];
    XCTAssertEqualObjects(data16_ref, coreData.sensitiveData);
    XCTAssertEqualObjects(data16_ref, data16_imm);
    coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:data16_mut];
    XCTAssertEqualObjects(data16_ref, coreData.sensitiveData);
    XCTAssertEqualObjects(zero16, data16_mut);
    
    coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:data24_imm];
    XCTAssertEqualObjects(data24_ref, coreData.sensitiveData);
    XCTAssertEqualObjects(data24_ref, data24_imm);
    coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:data24_mut];
    XCTAssertEqualObjects(data24_ref, coreData.sensitiveData);
    XCTAssertEqualObjects(zero24, data24_mut);
}

- (void) testCoreDataNilInit
{
    PowerAuthCoreData * coreData = [[PowerAuthCoreData alloc] initWithData:nil];
    XCTAssertNotNil(coreData.sensitiveData);
    XCTAssertEqual(0, coreData.sensitiveData.length);

    coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:nil];
    XCTAssertNotNil(coreData.sensitiveData);
    XCTAssertEqual(0, coreData.sensitiveData.length);
    
    coreData = [[PowerAuthCoreData alloc] initWithData:[NSData data]];
    XCTAssertNotNil(coreData.sensitiveData);
    XCTAssertEqual(0, coreData.sensitiveData.length);

    coreData = [[PowerAuthCoreData alloc] initWithDataAndClearSource:[NSMutableData data]];
    XCTAssertNotNil(coreData.sensitiveData);
    XCTAssertEqual(0, coreData.sensitiveData.length);
}

- (NSData*) zeroBytes:(NSUInteger)length mutable:(BOOL)mutable
{
    NSMutableData * data = [NSMutableData data];
    data.length = length;
    if (mutable) {
        return data;
    }
    return [NSData dataWithData:data];
}

@end

@implementation NSData (PA_immutable)
- (NSData*) immutableCopy
{
    return [NSData dataWithBytes:self.bytes length:self.length];
}
@end
