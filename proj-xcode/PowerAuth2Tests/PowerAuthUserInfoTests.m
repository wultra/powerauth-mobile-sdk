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

#import <XCTest/XCTest.h>
@import PowerAuth2;

#import "PowerAuthUserInfo+Private.h"

@interface PowerAuthUserInfoTests : XCTestCase
@end

@implementation PowerAuthUserInfoTests

- (void) testEmptyObjectCreation
{
    PowerAuthUserInfo * info = [[PowerAuthUserInfo alloc] initWithDictionary:nil];
    XCTAssertNil(info);
    PowerAuthUserAddress * address = [[PowerAuthUserAddress alloc] initWithDictionary:nil];
    XCTAssertNil(address);
    
    info = [[PowerAuthUserInfo alloc] initWithDictionary:@{}];
    XCTAssertNotNil(info);
    XCTAssertNil(info.subject);
    XCTAssertNil(info.name);
    XCTAssertNil(info.givenName);
    XCTAssertNil(info.familyName);
    XCTAssertNil(info.middleName);
    XCTAssertNil(info.nickname);
    XCTAssertNil(info.preferredUsername);
    XCTAssertNil(info.profileUrl);
    XCTAssertNil(info.pictureUrl);
    XCTAssertNil(info.websiteUrl);
    XCTAssertNil(info.email);
    XCTAssertFalse(info.isEmailVerified);
    XCTAssertNil(info.phoneNumber);
    XCTAssertFalse(info.isPhoneNumberVerified);
    XCTAssertNil(info.gender);
    XCTAssertNil(info.birthdate);
    XCTAssertNil(info.zoneInfo);
    XCTAssertNil(info.locale);
    XCTAssertNil(info.address);
    XCTAssertNil(info.updatedAt);
                 
    address = [[PowerAuthUserAddress alloc] initWithDictionary:@{}];
    XCTAssertNotNil(address);
    XCTAssertNil(address.formatted);
    XCTAssertNil(address.street);
    XCTAssertNil(address.locality);
    XCTAssertNil(address.region);
    XCTAssertNil(address.postalCode);
    XCTAssertNil(address.country);
}

- (void) testStandardClaims
{
    NSInteger timestamp = [[NSDate date] timeIntervalSince1970];
    NSMutableDictionary * claims = [@{
        @"sub": @"123456",
        @"name": @"John Jacob Doe",
        @"given_name": @"John",
        @"family_name": @"Doe",
        @"middle_name": @"Jacob",
        @"nickname": @"jjd",
        @"preferred_username" : @"JacobTheGreat",
        @"profile": @"https://jjd.com/profile",
        @"picture": @"https://jjd.com/avatar.jpg",
        @"website": @"https://jjd.com",
        @"email": @"jacob@jjd.com",
        @"email_verified": @(YES),
        @"gender": @"male",
        @"birthdate": @"1984-02-21",
        @"zoneinfo": @"Europe/Prague",
        @"locale": @"en-US",
        @"phone_number": @"+1 (425) 555-1212",
        @"phone_number_verified": @(YES),
        @"address": @{
            @"formatted": @"Belehradska 858/23\r\n120 00 Prague - Vinohrady\r\nCzech Republic",
            @"street_address": @"Belehradska 858/23\r\nVinohrady",
            @"locality": @"Prague",
            @"region": @"Prague",
            @"postal_code": @"12000",
            @"country": @"Czech Republic"
        },
        @"updated_at": @(timestamp),
        @"custom_claim": @"Hello world!"
    } mutableCopy];
    
    PowerAuthUserInfo * info = [[PowerAuthUserInfo alloc] initWithDictionary:claims];
    XCTAssertNotNil(info);
    
    XCTAssertEqualObjects(@"123456", info.subject);
    XCTAssertEqualObjects(@"John Jacob Doe", info.name);
    XCTAssertEqualObjects(@"John", info.givenName);
    XCTAssertEqualObjects(@"Jacob", info.middleName);
    XCTAssertEqualObjects(@"Doe", info.familyName);
    XCTAssertEqualObjects(@"jjd", info.nickname);
    XCTAssertEqualObjects(@"JacobTheGreat", info.preferredUsername);
    XCTAssertEqualObjects(@"https://jjd.com/profile", info.profileUrl);
    XCTAssertEqualObjects(@"https://jjd.com/avatar.jpg", info.pictureUrl);
    XCTAssertEqualObjects(@"https://jjd.com", info.websiteUrl);
    XCTAssertEqualObjects(@"jacob@jjd.com", info.email);
    XCTAssertTrue(info.isEmailVerified);
    XCTAssertEqualObjects(@"+1 (425) 555-1212", info.phoneNumber);
    XCTAssertTrue(info.isPhoneNumberVerified);
    XCTAssertEqualObjects(@"male", info.gender);
    XCTAssertEqualObjects(@"Europe/Prague", info.zoneInfo);
    XCTAssertEqualObjects(@"en-US", info.locale);
    XCTAssertEqualObjects(@"Belehradska 858/23\n120 00 Prague - Vinohrady\nCzech Republic", info.address.formatted);
    XCTAssertEqualObjects(@"Belehradska 858/23\nVinohrady", info.address.street);
    XCTAssertEqualObjects(@"Prague", info.address.locality);
    XCTAssertEqualObjects(@"Prague", info.address.region);
    XCTAssertEqualObjects(@"12000", info.address.postalCode);
    XCTAssertEqualObjects(@"Czech Republic", info.address.country);
    XCTAssertEqualObjects(@"Hello world!", info.allClaims[@"custom_claim"]);
    
    XCTAssertEqualObjects(@(timestamp), @(info.updatedAt.timeIntervalSince1970));
    NSDateComponents * components = [[NSDateComponents alloc] init];
    components.day = 21;
    components.month = 2;
    components.year = 1984;
    components.calendar = [NSCalendar currentCalendar];
    XCTAssertEqualObjects(components.date, info.birthdate);
    
    // Now alter some variables
    
    claims[@"phone_number_verified"] = @NO;
    claims[@"email_verified"] = @NO;
    claims[@"birthdate"] = @"1977-10-09";
    claims[@"middle_name"] = [NSNull null];
    
    components.year = 1977;
    components.month = 10;
    components.day = 9;
    
    info = [[PowerAuthUserInfo alloc] initWithDictionary:claims];
    XCTAssertFalse(info.isEmailVerified);
    XCTAssertFalse(info.isPhoneNumberVerified);
    XCTAssertNil(info.middleName);
    XCTAssertEqualObjects(components.date, info.birthdate);
    
    claims[@"birthdate"] = [NSNull null];
    claims[@"updated_at"] = [NSNull null];
    claims[@"address"] = [NSNull null];
    
    info = [[PowerAuthUserInfo alloc] initWithDictionary:claims];
    XCTAssertNil(info.birthdate);
    XCTAssertNil(info.updatedAt);
    XCTAssertNil(info.address);
}

@end
