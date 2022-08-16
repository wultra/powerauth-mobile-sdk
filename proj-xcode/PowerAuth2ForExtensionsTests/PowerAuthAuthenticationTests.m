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

#import <XCTest/XCTest.h>
@import PowerAuth2ForExtensions;

#import "PowerAuthAuthentication+Private.h"
#import "PowerAuthMacros.h"

@interface PowerAuthAuthenticationTests : XCTestCase
@property (nonatomic, strong) NSData * customBiometryKey;
@property (nonatomic, strong) NSData * customPossessionKey;
@property (nonatomic, strong) NSString * biometryPrompt;
@property (nonatomic, strong) id biometryContext;
@end

@implementation PowerAuthAuthenticationTests

- (void) setUp
{
    self.customBiometryKey = [@"FakeBiometryKey" dataUsingEncoding:NSUTF8StringEncoding];
    self.customPossessionKey = [@"FakePossessionKey" dataUsingEncoding:NSUTF8StringEncoding];
    self.biometryPrompt = @"Authenticate with biometry";
    
#if PA2_HAS_LACONTEXT
    #define XCTAssertContextNil(x) XCTAssertNil(x)
    self.biometryContext = [[LAContext alloc] init];
#else
    #define XCTAssertContextNil(x)
#endif // PA2_HAS_LACONTEXT
    
    PowerAuthLogSetEnabled(YES);
}

- (void) testSignPossessionOnly
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possession];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertNil(auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
}

- (void) testSignPossessionWithPassword
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithPassword:@"1234"];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertNil(auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithPassword:@"4321" customPossessionKey:_customPossessionKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"4321", auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertEqualObjects(self.customPossessionKey, auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
}

- (void) testSignPossessionWithBiometry
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithBiometry];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertNil(auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);

    auth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:_customBiometryKey customPossessionKey:_customPossessionKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertEqualObjects(self.customBiometryKey, auth.overridenBiometryKey);
    XCTAssertEqualObjects(self.customPossessionKey, auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryPrompt:_biometryPrompt];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertEqualObjects(_biometryPrompt, auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertNil(auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryPrompt:_biometryPrompt customPossessionKey:_customPossessionKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertEqualObjects(_biometryPrompt, auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertEqualObjects(self.customPossessionKey, auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
    
#if PA2_HAS_LACONTEXT
    auth = [PowerAuthAuthentication possessionWithBiometryContext:_biometryContext];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertEqualObjects(self.biometryContext, auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertNil(auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryContext:_biometryContext customPossessionKey:_customPossessionKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertEqualObjects(self.biometryContext, auth.biometryContext);
    XCTAssertNil(auth.overridenBiometryKey);
    XCTAssertEqualObjects(self.customPossessionKey, auth.overridenPossessionKey);
    XCTAssertTrue([auth validateUsage:NO]);
#endif // PA2_HAS_LACONTEXT
}

- (void) testLegacyObject
{
    PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
    XCTAssertFalse([auth validateUsage:NO]);
    XCTAssertFalse([auth validateUsage:YES]);
}

@end
