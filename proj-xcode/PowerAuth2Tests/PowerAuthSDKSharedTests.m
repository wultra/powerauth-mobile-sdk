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
	
	NSOperationQueue * _app1Queue;
	NSOperationQueue * _app2Queue;
	
	AsyncHelper * _waitForQueuesTask;
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

- (void) tearDown
{
	[self waitForTestQueues];
	_app1Queue.suspended = YES;
	_app2Queue.suspended = YES;
	
	[super tearDown];
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

- (void) prepareTestQueues
{
	if (_app1Queue || _app2Queue) {
		return;
	}
	_app1Queue = [[NSOperationQueue alloc] init];
	_app1Queue.maxConcurrentOperationCount = 1;
	_app1Queue.name = @"App1Thread";
	_app2Queue = [[NSOperationQueue alloc] init];
	_app2Queue.maxConcurrentOperationCount = 1;
	_app2Queue.name = @"App2Thread";
}

- (void) waitForTestQueues
{
	if (_app1Queue && _app2Queue) {
		__block volatile int completion = 2;
		[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			_waitForQueuesTask = waiting;
			void (^block)(void) = ^{
				if (--completion == 0) {
					[waiting reportCompletion:nil];
				}
			};
			[_app1Queue addOperationWithBlock:block];
			[_app2Queue addOperationWithBlock:block];
		}];
		_waitForQueuesTask = nil;
		[_app1Queue waitUntilAllOperationsAreFinished];
		[_app2Queue waitUntilAllOperationsAreFinished];
	}
}

#pragma mark - Integration tests

- (void) testConcurrentSignatureCalculations
{
	if (![self prepareAltSdk]) {
		XCTFail(@"Failed to initialize SDK objects");
		return;
	}
	[self.helper createActivation:YES];
	PowerAuthAuthentication * credentials = self.helper.authPossessionWithKnowledge;
	XCTAssertTrue([self.sdk hasValidActivation]);
	XCTAssertTrue([_altSdk hasValidActivation]);
	
	[self prepareTestQueues];
	[_app1Queue addOperationWithBlock:^{
		@try {
			for (int i = 0; i < 50; i++) {
				[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
					if (i % 5 == 0) {
						[self.sdk fetchActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error) {
							XCTAssertNotNil(status);
							[waiting reportCompletion:nil];
						}];
					} else {
						[self.sdk validatePasswordCorrect:credentials.usePassword callback:^(NSError * error) {
							XCTAssertNil(error);
							[waiting reportCompletion:nil];
						}];
					}
				}];
				[_waitForQueuesTask extendWaitingTime];
			}
		} @catch (NSException *exception) {
			XCTFail(@"Test failed with exception %@", exception);
		}
	}];
	[_app2Queue addOperationWithBlock:^{
		@try {
			for (int i = 0; i < 50; i++) {
				[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
					if (i % 7 == 0) {
						[self.sdk fetchActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error) {
							XCTAssertNotNil(status);
							[waiting reportCompletion:nil];
						}];
					} else {
						[_altSdk validatePasswordCorrect:credentials.usePassword callback:^(NSError * error) {
							XCTAssertNil(error);
							[waiting reportCompletion:nil];
						}];
					}
				}];
				[_waitForQueuesTask extendWaitingTime];
			}
		} @catch (NSException *exception) {
			XCTFail(@"Test failed with exception %@", exception);
		}
	}];
	[self waitForTestQueues];
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
	PowerAuthAuthentication * credentials = [self.helper createAuthentication];
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
	
	// Keep activation data in the helper to remove activation automatically at the end of the test.
	[self.helper assignCustomActivationData:activationData activationResult:activationResult credentials:credentials];
	
	XCTAssertTrue([self.sdk hasPendingActivation]);
	XCTAssertFalse([_altSdk hasValidActivation]);
	XCTAssertFalse([_altSdk hasPendingActivation]);
	
	PowerAuthExternalPendingOperation * extOp2 = _altSdk.externalPendingOperation;
	XCTAssertNotNil(extOp2);	// Other instance must have data
	XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, extOp2.externalOperationType);
	XCTAssertTrue([_app1 isEqualToString:extOp2.externalApplicationId]);
	
	BOOL result = [self.sdk commitActivationWithPassword:credentials.usePassword error:nil];
	XCTAssertTrue(result);
	
	XCTAssertTrue([self.sdk hasValidActivation]);
	XCTAssertTrue([_altSdk hasValidActivation]);
	XCTAssertNil([self.sdk externalPendingOperation]);
	XCTAssertNil([_altSdk externalPendingOperation]);
	
	// Commit activation on the server.
	[self.helper.testServerApi commitActivation:activationData.activationId];
	
	PowerAuthActivationStatus * status1 = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[self.sdk fetchActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error) {
			[waiting reportCompletion:status];
		}];
	}];
	XCTAssertNotNil(status1);
	XCTAssertEqual(PowerAuthActivationState_Active, status1.state);
	
	PowerAuthActivationStatus * status2 = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[_altSdk fetchActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error) {
			[waiting reportCompletion:status];
		}];
	}];
	XCTAssertNotNil(status2);
	XCTAssertEqual(PowerAuthActivationState_Active, status2.state);
}

@end