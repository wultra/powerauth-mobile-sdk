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

#import <XCTest/XCTest.h>

@import PowerAuth2;

/**
The `PowerAuthActivationTests` test class validates `PowerAuthActivation` object logic.
*/
@interface PowerAuthActivationTests : XCTestCase
@end

@implementation PowerAuthActivationTests

#pragma mark - Code

- (void) testRegularActivation
{
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithActivationCode:@"VVVVV-VVVVV-VVVVV-VTFVA" name:nil error:&error];
    XCTAssertNotNil(act1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CODE", act1.activationType);
    XCTAssertEqualObjects(@{@"code":@"VVVVV-VVVVV-VVVVV-VTFVA"}, act1.identityAttributes);
    XCTAssertEqualObjects(@"VVVVV-VVVVV-VVVVV-VTFVA", act1.activationCode.activationCode);
    XCTAssertNil(act1.name);
    XCTAssertNil(act1.extras);
    XCTAssertNil(act1.customAttributes);
    XCTAssertTrue([act1 validate]);
    
    PowerAuthActivation * act2 = [PowerAuthActivation activationWithActivationCode:@"3PZ2Z-DOXSL-PSSQI-I5VBA#MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw=="
                                                                              name:@"Troyplatnitchka"
                                                                             error:&error];
    XCTAssertNotNil(act2);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CODE", act2.activationType);
    XCTAssertEqualObjects(@{@"code":@"3PZ2Z-DOXSL-PSSQI-I5VBA"}, act2.identityAttributes);
    XCTAssertEqualObjects(@"3PZ2Z-DOXSL-PSSQI-I5VBA", act2.activationCode.activationCode);
    XCTAssertEqualObjects(@"MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw==", act2.activationCode.activationSignature);
    XCTAssertEqualObjects(@"Troyplatnitchka", act2.name);
    XCTAssertTrue([act2 validate]);
    
    PowerAuthActivation * act3 = [[PowerAuthActivation activationWithActivationCode:@"55555-55555-55555-55YMA"
                                                                               name:@"Troyplatnitchka"
                                                                              error:&error] withAdditionalActivationOtp:@"1234"];
    XCTAssertNotNil(act3);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CODE", act3.activationType);
    XCTAssertEqualObjects(@{@"code":@"55555-55555-55555-55YMA"}, act3.identityAttributes);
    XCTAssertEqualObjects(@"55555-55555-55555-55YMA", act3.activationCode.activationCode);
    XCTAssertEqualObjects(@"Troyplatnitchka", act3.name);
    XCTAssertEqualObjects(@"1234", act3.additionalActivationOtp);
    XCTAssertTrue([act3 validate]);
}

- (void) testRegularActivationInvalid
{
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithActivationCode:@"1234" name:nil error:&error];
    XCTAssertNil(act1);
    XCTAssertTrue([PowerAuthErrorDomain isEqualToString:error.domain]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationCode, error.code);
}


#pragma mark - Recovery

- (void) testRecoveryActivation
{
    id act1Identity = @{@"recoveryCode" : @"VVVVV-VVVVV-VVVVV-VTFVA" , @"puk" : @"0123456789"};
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithRecoveryCode:@"VVVVV-VVVVV-VVVVV-VTFVA" recoveryPuk:@"0123456789" name:nil error:&error];
    XCTAssertNotNil(act1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"RECOVERY", act1.activationType);
    XCTAssertEqualObjects(act1Identity, act1.identityAttributes);
    XCTAssertNil(act1.activationCode);
    XCTAssertNil(act1.name);
    XCTAssertNil(act1.extras);
    XCTAssertNil(act1.customAttributes);
    XCTAssertTrue([act1 validate]);
    
    id act2Identity = @{@"recoveryCode" : @"3PZ2Z-DOXSL-PSSQI-I5VBA" , @"puk" : @"0123456789"};
    PowerAuthActivation * act2 = [PowerAuthActivation activationWithRecoveryCode:@"R:3PZ2Z-DOXSL-PSSQI-I5VBA" recoveryPuk:@"0123456789" name:@"John Tramonta" error:nil];
    XCTAssertNotNil(act2);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"RECOVERY", act2.activationType);
    XCTAssertEqualObjects(act2Identity, act2.identityAttributes);
    XCTAssertNil(act2.activationCode);
    XCTAssertEqualObjects(@"John Tramonta", act2.name);
    XCTAssertTrue([act2 validate]);
}

- (void) testRecoveryActivationInvalid
{
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithRecoveryCode:@"12345" recoveryPuk:@"0123456789" name:nil error:&error];
    XCTAssertNil(act1);
    XCTAssertTrue([PowerAuthErrorDomain isEqualToString:error.domain]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationCode, error.code);
    PowerAuthActivation * act2 = [PowerAuthActivation activationWithRecoveryCode:@"3PZ2Z-DOXSL-PSSQI-I5VBA" recoveryPuk:@"1234" name:nil error:&error];
    XCTAssertNil(act2);
    XCTAssertTrue([PowerAuthErrorDomain isEqualToString:error.domain]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationCode, error.code);
    PowerAuthActivation * act3 = [[PowerAuthActivation activationWithRecoveryCode:@"VVVVV-VVVVV-VVVVV-VTFVA" recoveryPuk:@"0123456789" name:nil error:&error] withAdditionalActivationOtp:@"1234"];
    XCTAssertNotNil(act3);
    error = [act3 validateAndGetError];
    XCTAssertNotNil(error);
    XCTAssertTrue([PowerAuthErrorDomain isEqualToString:error.domain]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationData, error.code);
}

#pragma mark - OIDC

- (void) testOidcActivation
{
    NSString * providerId = @"abc123";
    NSString * code = @"ABCDEFGH";
    NSString * nonce = @"K1mP3rT9bQ8lV6zN7sW2xY4dJ5oU0fA1gH29o";
    NSString * codeVerifier = @"G3hsI1KZX1o~K0p-5lT3F7yZ4bC8dE2jX9aQ6nO2rP3uS7wT5mV8jW1oY6xB3sD09tR4vU3qM1nG7kL6hV5wY2pJ0aF3eK9dQ8xN4mS2zB7oU5tL1cJ3vX6yP8rE2wO9n";
    id act1Identity = @{ @"method": @"oidc", @"providerId": providerId, @"code": code, @"nonce": nonce };
    id act2Identity = @{ @"method": @"oidc", @"providerId": providerId, @"code": code, @"nonce": nonce, @"codeVerifier": codeVerifier };
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithOidcProviderId:providerId code:code nonce:nonce codeVerifier:nil error:&error];
    XCTAssertNotNil(act1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"DIRECT", act1.activationType);
    XCTAssertEqualObjects(act1Identity, act1.identityAttributes);
    XCTAssertNil(act1.activationCode);
    XCTAssertNil(act1.name);
    XCTAssertNil(act1.extras);
    XCTAssertNil(act1.customAttributes);
    XCTAssertTrue([act1 validate]);

    PowerAuthActivation * act2 = [PowerAuthActivation activationWithOidcProviderId:providerId code:code nonce:nonce codeVerifier:codeVerifier error:&error];
    XCTAssertNotNil(act2);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"DIRECT", act2.activationType);
    XCTAssertEqualObjects(act2Identity, act2.identityAttributes);
    XCTAssertNil(act2.activationCode);
    XCTAssertNil(act2.name);
    XCTAssertNil(act2.extras);
    XCTAssertNil(act2.customAttributes);
    XCTAssertTrue([act2 validate]);
}

#pragma mark - Custom

- (void) testCustomActivation
{
    id act1Identity = @{ @"login" : @"johntramonta", @"pass" : @"nbusr123" };
    id act1IdentityExp = @{ @"login" : @"johntramonta", @"pass" : @"nbusr123" };
    
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithIdentityAttributes:act1Identity name:nil error:&error];
    XCTAssertNotNil(act1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CUSTOM", act1.activationType);
    XCTAssertEqualObjects(act1IdentityExp, act1.identityAttributes);
    XCTAssertNil(act1.activationCode);
    XCTAssertNil(act1.name);
    XCTAssertNil(act1.extras);
    XCTAssertNil(act1.customAttributes);
    XCTAssertTrue([act1 validate]);
    
    id act2Identity = @{ @"username" : @"elvis", @"password" : @"lives" };
    id act2IdentityExp = @{ @"username" : @"elvis", @"password" : @"lives" };
    
    PowerAuthActivation * act2 = [PowerAuthActivation activationWithIdentityAttributes:act2Identity name:@"Elvis" error:&error];
    XCTAssertNotNil(act2);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CUSTOM", act2.activationType);
    XCTAssertEqualObjects(act2IdentityExp, act2.identityAttributes);
    XCTAssertNil(act2.activationCode);
    XCTAssertEqualObjects(@"Elvis", act2.name);
    XCTAssertTrue([act2 validate]);
}

- (void) testCustomActivationInvalid
{
    NSError * error = nil;
    PowerAuthActivation * act1 = [PowerAuthActivation activationWithIdentityAttributes:@{} name:nil error:&error];
    XCTAssertNil(act1);
    PowerAuthActivation * act2 = [[PowerAuthActivation activationWithIdentityAttributes:@{ @"username" : @"elvis", @"password" : @"lives" } name:nil error:&error] withAdditionalActivationOtp:@"1234"];
    XCTAssertNotNil(act2);
    error = [act2 validateAndGetError];
    XCTAssertNotNil(error);
    XCTAssertTrue([PowerAuthErrorDomain isEqualToString:error.domain]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationData, error.code);
}

#pragma mark - Customization

- (void) testObjectCustomization
{
    // Regular
    id expectedCustomAttrs = @{@"isPrimary":@(NO)};
    id expectedExtras = @"FL:123";
    NSError * error = nil;
    PowerAuthActivation * act1 = [[[[PowerAuthActivation activationWithActivationCode:@"VVVVV-VVVVV-VVVVV-VTFVA" name:nil error:&error]
                                    withActivationName:@"foo"]
                                            withExtras:@"FL:123"]
                                  withCustomAttributes:@{@"isPrimary":@(NO)}];
    XCTAssertNotNil(act1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CODE", act1.activationType);
    XCTAssertEqualObjects(@{@"code":@"VVVVV-VVVVV-VVVVV-VTFVA"}, act1.identityAttributes);
    XCTAssertEqualObjects(@"VVVVV-VVVVV-VVVVV-VTFVA", act1.activationCode.activationCode);
    XCTAssertEqualObjects(@"foo", act1.name);
    XCTAssertEqualObjects(expectedExtras, act1.extras);
    XCTAssertEqualObjects(expectedCustomAttrs, act1.customAttributes);
    XCTAssertTrue([act1 validate]);
    
    // Recovery
    id act2Identity = @{@"recoveryCode" : @"3PZ2Z-DOXSL-PSSQI-I5VBA" , @"puk" : @"0123456789"};
    PowerAuthActivation * act2 = [[[PowerAuthActivation activationWithRecoveryCode:@"R:3PZ2Z-DOXSL-PSSQI-I5VBA"
                                                                       recoveryPuk:@"0123456789"
                                                                              name:@"John Tramonta"
                                                                             error:&error]
                                   withExtras:@"FL:123"]
                                  withCustomAttributes:@{@"isPrimary":@(NO)}];
    XCTAssertNotNil(act2);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"RECOVERY", act2.activationType);
    XCTAssertEqualObjects(act2Identity, act2.identityAttributes);
    XCTAssertNil(act2.activationCode);
    XCTAssertEqualObjects(@"John Tramonta", act2.name);
    XCTAssertEqualObjects(expectedExtras, act2.extras);
    XCTAssertEqualObjects(expectedCustomAttrs, act2.customAttributes);
    XCTAssertTrue([act2 validate]);
    
    // Custom
    id act3Identity = @{ @"username" : @"elvis", @"password" : @"lives" };
    id act3IdentityExp = @{ @"username" : @"elvis", @"password" : @"lives" };
    
    PowerAuthActivation * act3 = [[[PowerAuthActivation activationWithIdentityAttributes:act3Identity name:@"Elvis" error:&error]
                                   withExtras:@"FL:123"]
                                  withCustomAttributes:@{@"isPrimary":@(NO)}];
    XCTAssertNotNil(act3);
    XCTAssertNil(error);
    XCTAssertEqualObjects(@"CUSTOM", act3.activationType);
    XCTAssertEqualObjects(act3IdentityExp, act3.identityAttributes);
    XCTAssertNil(act3.activationCode);
    XCTAssertEqualObjects(@"Elvis", act3.name);
    XCTAssertEqualObjects(expectedExtras, act3.extras);
    XCTAssertEqualObjects(expectedCustomAttrs, act3.customAttributes);
    XCTAssertTrue([act3 validate]);
}

@end
