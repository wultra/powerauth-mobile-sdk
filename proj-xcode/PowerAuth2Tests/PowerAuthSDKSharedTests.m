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

#import "PowerAuthSDKDefaultTests.h"

@interface PowerAuthSDKSharedTests : PowerAuthSDKDefaultTests
@end

@implementation PowerAuthSDKSharedTests
{
	PowerAuthSdkTestHelper * _altHelper;
	PowerAuthSDK * _altSdk;
	NSString * _app1;
	NSString * _app2;
	NSString * _appGroupId;
	NSString * _instanceId;
}

- (void) setUp
{
	_app1 = @"appInstance_1";
	_app2 = @"appInstance_2";
#if TARGET_OS_MACCATALYST == 1
	_appGroupId = @"group.com.wultra.testGroup";
	_instanceId = @"SharedInstanceTests-Catalyst";
#else
	_appGroupId = @"com.dummyGroup";
	_instanceId = @"SharedInstanceTests";
#endif
	[super setUp];
	
}

- (void) prepareConfigs:(PowerAuthConfiguration *)configuration
		 keychainConfig:(PowerAuthKeychainConfiguration *)keychainConfiguration
		   clientConfig:(PowerAuthClientConfiguration *)clientConfiguration
{
	configuration.instanceId = _instanceId;
	PowerAuthSharingConfiguration * sharingConfig = [[PowerAuthSharingConfiguration alloc] initWithAppGroup:_appGroupId appIdentifier:_app1];
	configuration.sharingConfiguration = sharingConfig;
}

- (BOOL) prepareAltSdk
{
	if (!self.sdk) {
		return NO;
	}
	
	PowerAuthConfiguration * altConfig = [self.helper.sdk.configuration copy];
	altConfig.sharingConfiguration = [[PowerAuthSharingConfiguration alloc] initWithAppGroup:_appGroupId appIdentifier:_app2];
	_altHelper = [PowerAuthSdkTestHelper clone:self.helper withConfiguration:altConfig];
	_altSdk = _altHelper.sdk;
	
	return _altSdk != nil;
}

- (void) testConcurrentSignatureCalculations
{
	if (![self prepareAltSdk]) {
		XCTFail(@"Failed to initialize SDK objects");
		return;
	}
}

- (void) testConcurrentActivation
{
	if (![self prepareAltSdk]) {
		XCTFail(@"Failed to initialize SDK objects");
		return;
	}
	
	PATSInitActivationResponse * activationData = [self.helper prepareActivation:YES activationOtp:nil];
	XCTAssertNotNil(activationData);
	if (!activationData) return;
	
	XCTAssertFalse([self.sdk hasValidActivation]);
	XCTAssertFalse([_altSdk hasValidActivation]);
	PowerAuthActivationResult * activationResult = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:[activationData activationCodeWithSignature] name:nil error:nil];
		id task = [self.sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
			[waiting reportCompletion:result];
		}];
		XCTAssertNotNil(task);
		
		PowerAuthExternalPendingOperation * extOp1 = self.sdk.externalPendingOperation;
		XCTAssertNil(extOp1);		// Instance that initiated activation, must return nil.
		
		PowerAuthExternalPendingOperation * extOp2 = _altSdk.externalPendingOperation;
		XCTAssertNotNil(extOp2);	// Other instance must have data
		XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, extOp2.externalOperationType);
		XCTAssertTrue([_app1 isEqualToString:extOp2.externalApplicationId]);
		
		id task2 = [_altSdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
			XCTAssertEqual(PowerAuthErrorCode_ExternalPendingOperation, error.powerAuthErrorCode);
			XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, error.powerAuthExternalPendingOperation.externalOperationType);
			XCTAssertTrue([_app1 isEqualToString:error.powerAuthExternalPendingOperation.externalApplicationId]);
		}];
		XCTAssertNil(task2);
		[task2 cancel];
	}];
	XCTAssertNotNil(activationResult);
	if (!activationResult) return;
	
	XCTAssertTrue([self.sdk hasPendingActivation]);
	XCTAssertFalse([_altSdk hasValidActivation]);
	XCTAssertFalse([_altSdk hasPendingActivation]);
	
	PowerAuthExternalPendingOperation * extOp2 = _altSdk.externalPendingOperation;
	XCTAssertNotNil(extOp2);	// Other instance must have data
	XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, extOp2.externalOperationType);
	XCTAssertTrue([_app1 isEqualToString:extOp2.externalApplicationId]);
	
	PowerAuthAuthentication * credentials = [self.helper createAuthentication];
	BOOL result = [self.sdk commitActivationWithPassword:credentials.usePassword error:nil];
	XCTAssertTrue(result);
	
	XCTAssertTrue([self.sdk hasValidActivation]);
	XCTAssertTrue([_altSdk hasValidActivation]);
	XCTAssertNil([self.sdk externalPendingOperation]);
	XCTAssertNil([_altSdk externalPendingOperation]);
}

@end
