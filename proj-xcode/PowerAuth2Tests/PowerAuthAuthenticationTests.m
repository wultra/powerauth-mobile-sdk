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
@import PowerAuth2;

#import "PowerAuthAuthentication+Private.h"
#import "PowerAuthMacros.h"
#import "PowerAuthCorePasswordHelper.h"

@interface PowerAuthAuthenticationTests : XCTestCase
@property (nonatomic, strong) PowerAuthCoreData * customBiometryKey;
@property (nonatomic, strong) PowerAuthCoreData * customPossessionKey;
@property (nonatomic, strong) NSString * biometryPrompt;
@property (nonatomic, strong) id biometryContext;
@end

@implementation PowerAuthAuthenticationTests

- (void) setUp
{
    self.customBiometryKey = [PowerAuthCoreSession generateFactorKekForProtocolVersion:PowerAuthCoreProtocolVersion_V3 error:nil];
    self.customPossessionKey = [PowerAuthCoreSession generateFactorKekForProtocolVersion:PowerAuthCoreProtocolVersion_V3 error:nil];
    self.biometryPrompt = @"Authenticate with biometry";
    
#if PA2_HAS_LACONTEXT
    #define XCTAssertContextNil(x) XCTAssertNil(x)
    self.biometryContext = [[LAContext alloc] init];
#else
    #define XCTAssertContextNil(x)
#endif // PA2_HAS_LACONTEXT
    
    PowerAuthLogSetEnabled(YES);
}

- (void) testPersistWithPassword
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication persistWithPassword:@"1234"];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
        
    // core password variants
    
    auth = [PowerAuthAuthentication persistWithCorePassword:[PowerAuthCorePassword passwordWithString:@"1234"]];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
}

- (void) testPersistWithPasswordAndBiometry
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication persistWithPasswordAndBiometry:@"1234"];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
    
    auth = [PowerAuthAuthentication persistWithPasswordAndBiometry:@"4321" customBiometryKey:_customBiometryKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertEqualObjects(@"4321", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertEqualObjects(self.customBiometryKey, auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
    
    // core password variants
    
    auth = [PowerAuthAuthentication persistWithCorePasswordAndBiometry:[PowerAuthCorePassword passwordWithString:@"1234"]];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
    
    auth = [PowerAuthAuthentication persistWithCorePasswordAndBiometry:[PowerAuthCorePassword passwordWithString:@"4321"] customBiometryKey:_customBiometryKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertEqualObjects(@"4321", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertEqualObjects(self.customBiometryKey, auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:YES]);
}

- (void) testSignPossessionOnly
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possession];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
}

- (void) testSignPossessionWithPassword
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithPassword:@"1234"];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
        
    // core password variants
    
    auth = [PowerAuthAuthentication possessionWithCorePassword:[PowerAuthCorePassword passwordWithString:@"1234"]];
    XCTAssertTrue(auth.usePossession);
    XCTAssertFalse(auth.useBiometry);
    XCTAssertEqualObjects(@"1234", auth.password.extractedPassword);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
}

- (void) testSignPossessionWithBiometry
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithBiometry];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);

    auth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:_customBiometryKey];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertEqualObjects(self.customBiometryKey, auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryPrompt:_biometryPrompt];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertEqualObjects(_biometryPrompt, auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryPrompt:_biometryPrompt];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertEqualObjects(_biometryPrompt, auth.biometryPrompt);
    XCTAssertContextNil(auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
    
#if PA2_HAS_LACONTEXT
    auth = [PowerAuthAuthentication possessionWithBiometryContext:_biometryContext];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertEqualObjects(self.biometryContext, auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
    
    auth = [PowerAuthAuthentication possessionWithBiometryContext:_biometryContext];
    XCTAssertTrue(auth.usePossession);
    XCTAssertTrue(auth.useBiometry);
    XCTAssertNil(auth.password);
    XCTAssertNil(auth.biometryPrompt);
    XCTAssertEqualObjects(self.biometryContext, auth.biometryContext);
    XCTAssertNil(auth.customBiometryKey);
    XCTAssertNil([auth validateUsage:NO]);
#endif // PA2_HAS_LACONTEXT
}

- (void) testWrongUsage
{
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possession];
    NSError * error;
    error = [auth validateUsage:YES];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication persistWithPassword:@"Hello"];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication persistWithCorePassword:[PowerAuthCorePassword passwordWithString:@"Hello"]];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    
#pragma clang diagnostic push   // PA2_DEPRECATED(2.0.0)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // custom possession key
    auth = [PowerAuthAuthentication persistWithPassword:@"4321" customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:YES];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication persistWithCorePassword:[PowerAuthCorePassword passwordWithString:@"4321"] customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:YES];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication persistWithPasswordAndBiometry:@"4321" customBiometryKey:_customBiometryKey customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:YES];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication persistWithCorePasswordAndBiometry:[PowerAuthCorePassword passwordWithString:@"4321"] customBiometryKey:_customBiometryKey customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:YES];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    
    auth = [PowerAuthAuthentication possessionWithPassword:@"4321" customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication possessionWithCorePassword:[PowerAuthCorePassword passwordWithString:@"4321"] customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:_customBiometryKey customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication possessionWithBiometryPrompt:_biometryPrompt customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:NO];
#if PA2_HAS_LACONTEXT
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
    auth = [PowerAuthAuthentication possessionWithBiometryContext:_biometryContext customPossessionKey:_customPossessionKey];
    error = [auth validateUsage:NO];
    XCTAssertEqual(PowerAuthErrorCode_WrongParameter, error.powerAuthErrorCode);
#endif // PA2_HAS_LACONTEXT
#pragma clang diagnostic pop
}

@end
