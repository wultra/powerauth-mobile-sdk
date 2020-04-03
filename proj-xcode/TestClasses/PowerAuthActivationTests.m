/*
 * Copyright 2020 Wultra s.r.o.
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

/**
The `PowerAuthActivationTests` test class validates `PowerAuthActivation` object logic.
*/
@interface PowerAuthActivationTests : XCTestCase
@end

@implementation PowerAuthActivationTests

#pragma mark - Code

- (void) testRegularActivation
{
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithActivationCode:@"VVVVV-VVVVV-VVVVV-VTFVA" name:nil];
	XCTAssertNotNil(act1);
	XCTAssertEqualObjects(@"CODE", act1.activationType);
	XCTAssertEqualObjects(@{@"code":@"VVVVV-VVVVV-VVVVV-VTFVA"}, act1.identityAttributes);
	XCTAssertEqualObjects(@"VVVVV-VVVVV-VVVVV-VTFVA", act1.activationCode.activationCode);
	XCTAssertNil(act1.name);
	XCTAssertNil(act1.extras);
	XCTAssertNil(act1.customAttributes);
	XCTAssertTrue([act1 validate]);
	
	PowerAuthActivation * act2 = [PowerAuthActivation activationWithActivationCode:@"3PZ2Z-DOXSL-PSSQI-I5VBA#MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw=="
																			  name:@"Troyplatnitchka"];
	XCTAssertNotNil(act2);
	XCTAssertEqualObjects(@"CODE", act2.activationType);
	XCTAssertEqualObjects(@{@"code":@"3PZ2Z-DOXSL-PSSQI-I5VBA"}, act2.identityAttributes);
	XCTAssertEqualObjects(@"3PZ2Z-DOXSL-PSSQI-I5VBA", act2.activationCode.activationCode);
	XCTAssertEqualObjects(@"MEQCIHP3LQ7WLDEPe8WCgdQ8CSwyxbErroYlGO+K6pIX1JyhAiAn6wEnaNp1mDdKlWb16Ma8eTKycRcZ+75TYV/zn0yvFw==", act2.activationCode.activationSignature);
	XCTAssertEqualObjects(@"Troyplatnitchka", act2.name);
	XCTAssertTrue([act2 validate]);
	
	PowerAuthActivation * act3 = [[PowerAuthActivation activationWithActivationCode:@"55555-55555-55555-55YMA"
																			   name:@"Troyplatnitchka"] withAdditionalActivationOtp:@"1234"];
	XCTAssertNotNil(act3);
	XCTAssertEqualObjects(@"CODE", act3.activationType);
	XCTAssertEqualObjects(@{@"code":@"55555-55555-55555-55YMA"}, act3.identityAttributes);
	XCTAssertEqualObjects(@"55555-55555-55555-55YMA", act3.activationCode.activationCode);
	XCTAssertEqualObjects(@"Troyplatnitchka", act3.name);
	XCTAssertEqualObjects(@"1234", act3.additionalActivationOtp);
	XCTAssertTrue([act3 validate]);
}

- (void) testRegularActivationInvalid
{
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithActivationCode:@"1234" name:nil];
	XCTAssertNil(act1);
}


#pragma mark - Recovery

- (void) testRecoveryActivation
{
	id act1Identity = @{@"recoveryCode" : @"VVVVV-VVVVV-VVVVV-VTFVA" , @"puk" : @"0123456789"};
	
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithRecoveryCode:@"VVVVV-VVVVV-VVVVV-VTFVA" recoveryPuk:@"0123456789" name:nil];
	XCTAssertNotNil(act1);
	XCTAssertEqualObjects(@"RECOVERY", act1.activationType);
	XCTAssertEqualObjects(act1Identity, act1.identityAttributes);
	XCTAssertNil(act1.activationCode);
	XCTAssertNil(act1.name);
	XCTAssertNil(act1.extras);
	XCTAssertNil(act1.customAttributes);
	XCTAssertTrue([act1 validate]);
	
	id act2Identity = @{@"recoveryCode" : @"3PZ2Z-DOXSL-PSSQI-I5VBA" , @"puk" : @"0123456789"};
	PowerAuthActivation * act2 = [PowerAuthActivation activationWithRecoveryCode:@"R:3PZ2Z-DOXSL-PSSQI-I5VBA" recoveryPuk:@"0123456789" name:@"John Tramonta"];
	XCTAssertNotNil(act2);
	XCTAssertEqualObjects(@"RECOVERY", act2.activationType);
	XCTAssertEqualObjects(act2Identity, act2.identityAttributes);
	XCTAssertNil(act2.activationCode);
	XCTAssertEqualObjects(@"John Tramonta", act2.name);
	XCTAssertTrue([act2 validate]);
}

- (void) testRecoveryActivationInvalid
{
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithRecoveryCode:@"12345" recoveryPuk:@"0123456789" name:nil];
	XCTAssertNil(act1);
	PowerAuthActivation * act2 = [PowerAuthActivation activationWithRecoveryCode:@"3PZ2Z-DOXSL-PSSQI-I5VBA" recoveryPuk:@"1234" name:nil];
	XCTAssertNil(act2);
	PowerAuthActivation * act3 = [[PowerAuthActivation activationWithRecoveryCode:@"VVVVV-VVVVV-VVVVV-VTFVA" recoveryPuk:@"0123456789" name:nil] withAdditionalActivationOtp:@"1234"];
	XCTAssertNotNil(act3);
	XCTAssertFalse([act3 validate]);
}


#pragma mark - Custom

- (void) testCustomActivation
{
	id act1Identity = @{ @"login" : @"johntramonta", @"pass" : @"nbusr123" };
	id act1IdentityExp = @{ @"login" : @"johntramonta", @"pass" : @"nbusr123" };
	
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithIdentityAttributes:act1Identity name:nil];
	XCTAssertNotNil(act1);
	XCTAssertEqualObjects(@"CUSTOM", act1.activationType);
	XCTAssertEqualObjects(act1IdentityExp, act1.identityAttributes);
	XCTAssertNil(act1.activationCode);
	XCTAssertNil(act1.name);
	XCTAssertNil(act1.extras);
	XCTAssertNil(act1.customAttributes);
	XCTAssertTrue([act1 validate]);
	
	id act2Identity = @{ @"username" : @"elvis", @"password" : @"lives" };
	id act2IdentityExp = @{ @"username" : @"elvis", @"password" : @"lives" };
	
	PowerAuthActivation * act2 = [PowerAuthActivation activationWithIdentityAttributes:act2Identity name:@"Elvis"];
	XCTAssertNotNil(act2);
	XCTAssertEqualObjects(@"CUSTOM", act2.activationType);
	XCTAssertEqualObjects(act2IdentityExp, act2.identityAttributes);
	XCTAssertNil(act2.activationCode);
	XCTAssertEqualObjects(@"Elvis", act2.name);
	XCTAssertTrue([act2 validate]);
}

- (void) testCustomActivationInvalid
{
	PowerAuthActivation * act1 = [PowerAuthActivation activationWithIdentityAttributes:@{} name:nil];
	XCTAssertNil(act1);
	PowerAuthActivation * act2 = [[PowerAuthActivation activationWithIdentityAttributes:@{ @"username" : @"elvis", @"password" : @"lives" } name:nil] withAdditionalActivationOtp:@"1234"];
	XCTAssertNotNil(act2);
	XCTAssertFalse([act2 validate]);
}

#pragma mark - Customization

- (void) testObjectCustomization
{
	// Regular
	id expectedCustomAttrs = @{@"isPrimary":@(NO)};
	id expectedExtras = @"FL:123";
	
	PowerAuthActivation * act1 = [[[PowerAuthActivation activationWithActivationCode:@"VVVVV-VVVVV-VVVVV-VTFVA" name:nil]
								   withExtras:@"FL:123"]
								  withCustomAttributes:@{@"isPrimary":@(NO)}];
	XCTAssertNotNil(act1);
	XCTAssertEqualObjects(@"CODE", act1.activationType);
	XCTAssertEqualObjects(@{@"code":@"VVVVV-VVVVV-VVVVV-VTFVA"}, act1.identityAttributes);
	XCTAssertEqualObjects(@"VVVVV-VVVVV-VVVVV-VTFVA", act1.activationCode.activationCode);
	XCTAssertNil(act1.name);
	XCTAssertEqualObjects(expectedExtras, act1.extras);
	XCTAssertEqualObjects(expectedCustomAttrs, act1.customAttributes);
	XCTAssertTrue([act1 validate]);
	
	// Recovery
	id act2Identity = @{@"recoveryCode" : @"3PZ2Z-DOXSL-PSSQI-I5VBA" , @"puk" : @"0123456789"};
	PowerAuthActivation * act2 = [[[PowerAuthActivation activationWithRecoveryCode:@"R:3PZ2Z-DOXSL-PSSQI-I5VBA"
																	   recoveryPuk:@"0123456789"
																			  name:@"John Tramonta"]
								   withExtras:@"FL:123"]
								  withCustomAttributes:@{@"isPrimary":@(NO)}];
	XCTAssertNotNil(act2);
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
	
	PowerAuthActivation * act3 = [[[PowerAuthActivation activationWithIdentityAttributes:act3Identity name:@"Elvis"]
								   withExtras:@"FL:123"]
								  withCustomAttributes:@{@"isPrimary":@(NO)}];
	XCTAssertNotNil(act3);
	XCTAssertEqualObjects(@"CUSTOM", act3.activationType);
	XCTAssertEqualObjects(act3IdentityExp, act3.identityAttributes);
	XCTAssertNil(act3.activationCode);
	XCTAssertEqualObjects(@"Elvis", act3.name);
	XCTAssertEqualObjects(expectedExtras, act3.extras);
	XCTAssertEqualObjects(expectedCustomAttrs, act3.customAttributes);
	XCTAssertTrue([act3 validate]);
}

@end
