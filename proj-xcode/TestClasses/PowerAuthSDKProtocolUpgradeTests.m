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

#import <XCTest/XCTest.h>
#import "PowerAuthTestServerAPI.h"
#import "PowerAuthTestServerConfig.h"
#import "AsyncHelper.h"

#import "PowerAuth2.h"

/**
 The purpose of `PowerAuthSDKProtocolUpgradeTests` is to test protocol
 upgrade from one SDK version to another. Unfortunately, the upgrade
 could not be executed automatically, so you have to follow these steps:
	
 1. Checkout old SDK branch (for example, 0.20.x)
 2. Set `upgradeStep` to 1 in JSON test configuration
 3. Run 'testProtocolUpgrade' unit test to create an activation.
 4. Now checkout the new SDK branch (for exmample, 1.3.x)
 5. Set `upgradeStep` to 2 in JSON test configuration
 6. Run 'testProtocolUpgrade' unit test to test upgrade
 
 You should not run any other tests during the upgrade validation.
 */
@interface PowerAuthSDKProtocolUpgradeTests : XCTestCase
@end

@implementation PowerAuthSDKProtocolUpgradeTests
{
	PowerAuthTestServerConfig * _testServerConfig;	// Loaded config
	PowerAuthTestServerAPI * _testServerApi;		// SOAP connection
	PowerAuthConfiguration * _config;				// Default SDK config
	PowerAuthSDK * _sdk;							// Default SDK instance

	BOOL _hasConfig;
	BOOL _invalidConfig;
	
	NSInteger _upgradeStep;
	NSString * _upgradeOldProtocolVersion;
	NSString * _upgradeNewProtocolVersion;
	NSString * _upgradeProtocolVersion;
}

// -----------------------------------------------------------------------------------------
// Adjust following values to match requirements of current SDK branch.
//  - HAS_ASYNC_TASK_PROTOCOL
//      - set to '1' if async task used in SDK is still an object (SDKs older than 1.0.0)
//      - set to '0' if async task is a protocol.
//  - HAS_PENDING_COMMIT_STATE
//      - set to '1' if 'OTP_Used' state is deprecated or unavailable in current SDK.
//      - set to '0' if 'OTP_Used' state is still valid
//  - UPGRADE_OLD_PROTOCOL
//      - defines default version of protocol for "old" SDK
//  - UPGRADE_NEW_PROTOCOL
//      - defines default version of protocol for "new" SDK
// -----------------------------------------------------------------------------------------
#define HAS_ASYNC_TASK_PROTOCOL		0
#define HAS_PENDING_COMMIT_STATE	0

#define UPGRADE_OLD_PROTOCOL	@"2.1"
#define UPGRADE_NEW_PROTOCOL	@"3.1"

// Adjust SDK specific objects
#if HAS_ASYNC_TASK_PROTOCOL == 1
#define PA2TestsOperationTask 	id<PA2OperationTask>
#else
#define PA2TestsOperationTask 	PA2OperationTask*
#endif

#if HAS_PENDING_COMMIT_STATE == 1
#define PA2TestActivationState_PendingCommit	PA2ActivationState_PendingCommit
#else
#define PA2TestActivationState_PendingCommit	PA2ActivationState_OTP_Used
#endif

#pragma mark - Test setup

- (void)setUp
{
    [super setUp];
	[self runOnceForAllTests];
}

/**
 Loads a configuration from expected file, or creates a default one.
 */
- (BOOL) loadConfiguration
{
	NSBundle * bundle = [NSBundle bundleForClass:[self class]];
	NSString * path = [bundle pathForResource:@"TestConfig/Configuration" ofType:@"json"];
	if (path) {
		_testServerConfig = [PowerAuthTestServerConfig loadFromJsonFile:path];
		if (_testServerConfig == nil) {
			return NO;
		}
	} else {
		_testServerConfig = [PowerAuthTestServerConfig defaultConfig];
	}
	
	// Load protocol upgrade specific parameters
	_upgradeStep = [[_testServerConfig configValueForKey:@"upgradeStep" defaultValue:@0] integerValue];
	_upgradeOldProtocolVersion = [_testServerConfig configValueForKey:@"upgradeOldProtocolVersion" defaultValue:UPGRADE_OLD_PROTOCOL];
	_upgradeNewProtocolVersion = [_testServerConfig configValueForKey:@"upgradeNewProtocolVersion" defaultValue:UPGRADE_NEW_PROTOCOL];
	_upgradeProtocolVersion = _upgradeStep == 2 ? _upgradeNewProtocolVersion : _upgradeOldProtocolVersion;
	
	// Print report
	NSLog(@"=======================================================================");
	NSLog(@"The protocol upgrade tests will run against following servers:");
	NSLog(@"    REST API Server: %@", _testServerConfig.restApiUrl);
	NSLog(@"    SOAP API Server: %@", _testServerConfig.soapApiUrl);
	NSLog(@"               User: %@", _testServerConfig.userIdentifier);
	if (_upgradeStep > 0) {
		NSLog(@"            Upgrade: %@ step, with protocol %@", _upgradeStep == 2 ? @"Validate" : @"Create", _upgradeProtocolVersion);
	} else {
		NSLog(@"            Upgrade: Disabled");
	}
	NSLog(@"=======================================================================");
	
	return YES;
}

/**
 Performs one-time initialization for all unit tests. The result of calling this method is
 pepared all i-vars with runtime variables, like _sdk, _soapApiURL, etc...
 */
- (void) runOnceForAllTests
{
	PA2LogSetEnabled(YES);
	
	if (_hasConfig || _invalidConfig) {
		return;
	}
	
	// Prepare command
	BOOL result;
	result = [self loadConfiguration];
	XCTAssertTrue(result, @"The provided test configuration is wrong.");
	
	// Test connection to SOAP server
	if (result) {
		_testServerApi = [[PowerAuthTestServerAPI alloc] initWithConfiguration:_testServerConfig];
		result = [_testServerApi validateConnection];
		XCTAssertTrue(result, @"Connection to test server failed. Check debug log for details.");
	}
	// Create a configuration
	if (result) {
		_config = [[PowerAuthConfiguration alloc] init];
		_config.instanceId = @"ProtocolUpgradeTests";
		_config.baseEndpointUrl = _testServerConfig.restApiUrl;
		_config.appKey = _testServerApi.appVersion.applicationKey;
		_config.appSecret = _testServerApi.appVersion.applicationSecret;
		_config.masterServerPublicKey = _testServerApi.appDetail.masterPublicKey;
		result = [_config validateConfiguration];
		XCTAssertTrue(result, @"Constructed configuration is not valid.");
	}
	// Construct an PA-SDK object
	if (result) {
		_sdk = [[PowerAuthSDK alloc] initWithConfiguration:_config];
		
		result = _sdk != nil;
		
		XCTAssertTrue(result, @"PowerAuthSDK ended in unexpected state.");
	}
	_invalidConfig = result == NO;
	_hasConfig = YES;
}


#pragma mark - Helper utilities

/**
 Checks whether the test config is valid. You should use this macro in all unit tests
 defined in this class.
 */
#define CHECK_TEST_CONFIG()		\
	if (_invalidConfig) {		\
		XCTFail(@"Test configuration is not valid.");	\
		return;					\
	}

/**
 Checks boolean value in result local variable and returns |obj| value if contains NO.
 */
#define CHECK_RESULT_RET(obj)	\
	if (result == NO) {			\
		return obj;				\
	}

/**
 Creates a new PowerAuthAuthentication object with default configuration.
 */
- (PowerAuthAuthentication*) createAuthentication
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = NO;		// There's no human being involved in the automatic test :)
	auth.usePassword = @"supersecure";
	return auth;
}

/**
 Returns an activation status object. May return nil if status is not available yet, which is also valid operation.
 */
- (PA2ActivationStatus*) fetchActivationStatus
{
	BOOL taskShouldWork = [_sdk hasValidActivation];
	
	__block NSDictionary * activationStatusCustomObject = nil;
	__block NSError * fetchError = nil;
	PA2ActivationStatus * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Start a fetch task.
		PA2TestsOperationTask task = [_sdk fetchActivationStatusWithCallback:^(PA2ActivationStatus * status, NSDictionary * customObject, NSError * error) {
			activationStatusCustomObject = customObject;
			fetchError = error;
			[waiting reportCompletion:status];
		}];
		// Test whether the task should work.
		if (taskShouldWork) {
			XCTAssertNotNil(task);
		} else {
			XCTAssertNil(task);
		}
	}];
	if (taskShouldWork) {
		XCTAssertNotNil(result);
		return result;
	}
	return nil;
}

/**
 Validates password on server. Returns YES if password is valid.
 */
- (BOOL) checkForPassword:(NSString*)password
{
	BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		PA2TestsOperationTask task = [_sdk validatePasswordCorrect:password callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	return result;
}

#pragma mark - Integration tests

#pragma mark - Activation

/**
 Returns @[PATSInitActivationResponse, PowerAuthAuthentication, @(BOOL)] with activation data, authentication object,
 and result of activation. You can configure whether the activation can use optional signature during the activation
 and whether the activation should be removed automatically after the creation.
 */
- (NSArray*) createActivation:(BOOL)useSignature removeAfter:(BOOL)removeAfter
{
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	BOOL result;
	NSError * error;
	
	// We can't guarantee a sequence of tests, so reset the activation now
	[_sdk removeActivationLocal];
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	XCTAssertTrue([_sdk canStartActivation]);
	
	// 1) SERVER: initialize an activation on server (this is typically implemented in the internet banking application)
	PATSInitActivationResponse * activationData = [_testServerApi initializeActivation:_testServerConfig.userIdentifier];
	NSString * activationCode = useSignature ? [activationData activationCodeWithSignature] : [activationData activationCodeWithoutSignature];
	NSArray * preliminaryResult = @[activationData, @NO, [NSNull null]];
	
	__block NSString * activationFingerprint = nil;
	
	// 2) CLIENT: Start activation on client's side
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		NSString * activationName = _testServerConfig.userActivationName;
		PA2TestsOperationTask task = [_sdk createActivationWithName:activationName activationCode:activationCode callback:^(PA2ActivationResult * result, NSError * error) {
			activationFingerprint = result.activationFingerprint;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should not be cancelled
		XCTAssertNotNil(task);
		
	}] boolValue];
	XCTAssertTrue(result, @"Activation on client side did fail.");
	CHECK_RESULT_RET(preliminaryResult);
	
	XCTAssertTrue([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	XCTAssertFalse([_sdk canStartActivation]);
	
	
	// 2.1) CLIENT: Try to fetch status. At this point, it should not work! The activation is not completed yet.
	PA2ActivationStatus * activationStatus = [self fetchActivationStatus];
	XCTAssertNil(activationStatus);
	XCTAssertTrue([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	// 3) CLIENT: Now it's time to commit activation locally
	PowerAuthAuthentication * auth = [self createAuthentication];
	result = [_sdk commitActivationWithAuthentication:auth error:&error];
	CHECK_RESULT_RET(preliminaryResult);
	
	XCTAssertTrue(result, @"Client's commit failed.");
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertTrue([_sdk hasValidActivation]);
	
	// 3.1) CLIENT: Fetch status again. In this time, the operation should work and return OTP_USED
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	XCTAssertTrue(activationStatus.state == PA2TestActivationState_PendingCommit);
	
	// 4) SERVER: This is the last step of activation. We need to commit an activation on the server side.
	//            This is typically done internally on the server side and depends on activation flow
	//            in concrete internet banking project.
	result = [_testServerApi commitActivation:activationData.activationId];
	XCTAssertTrue(result, @"Server's commit failed");
	CHECK_RESULT_RET(preliminaryResult);
	
	// 5) CLIENT: Fetch status again. Now the state should be active
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	XCTAssertTrue(activationStatus.state == PA2ActivationState_Active);
	
	// Post activation steps...
	result = [_sdk.session.activationIdentifier isEqualToString:activationData.activationId];
	XCTAssertTrue(result, @"Activation identifier in session is different to identifier generated on the server.");
	CHECK_RESULT_RET(preliminaryResult);
	
	// Now it's time to validate activation status, created on the server
	PATSActivationStatus * serverActivationStatus = [_testServerApi getActivationStatus:activationData.activationId];
	result = serverActivationStatus != nil;
	CHECK_RESULT_RET(preliminaryResult);
	XCTAssertTrue([serverActivationStatus.activationName isEqualToString:_testServerConfig.userActivationName]);
	// Test whether the device's public key fingerprint is equal on server and client.
	XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationFingerprint]);
	
	// This is just a cleanup. If remove will fail, then we don't report an error
	if (removeAfter || !result) {
		if (!result) {
			NSLog(@"We're removing activation due to fact, that session creation failed.");
		}
		[self removeLastActivation:activationData];
	}
	
	return @[activationData, auth, @YES ];
}

/**
 Method will remove activation on the server. We're using SOAP message, because our SDK object doesn't have activation always
 identifier present in its structures.
 */
- (void) removeLastActivation:(PATSInitActivationResponse*)activationData
{
	NSString * activationId;
	if (activationData) {
		// If we have activation data, prefer that id.
		activationId = _sdk.session.activationIdentifier;
	}
	if (!activationId) {
		activationId = _sdk.session.activationIdentifier;
	}
	if (!activationId) {
		NSLog(@"WARNING: Unable to remove activation. This is not an error, but you'll see a lot of unfinished activations.");
	}
	[_testServerApi removeActivation:activationId];
}

#pragma mark - Protocol upgrade tests

- (void) testProtocolUpgrade
{
	if (_upgradeStep == 1) {
		[self createOldActivation];
	} else if (_upgradeStep == 2) {
		[self validateUpgrade];
	} else {
		NSLog(@"`upgradeStep` is not set in JSON configuration. Skipping execution of `testSdkProtocolUpgrade`.");
	}
}

static NSString * const s_PossessionFactorKey = @"upgradeTest_possessionFactor";
static NSString * const s_ActivationIdKey = @"upgradeTest_activationId";
static NSString * const s_StateDataKey = @"upgradeTest_stateDataKey";

- (void) createOldActivation
{
	CHECK_TEST_CONFIG();
	
	if ([_sdk hasValidActivation]) {
		NSLog(@"WARNING: There's some valid activation, removing it locally.");
		[_sdk removeActivationLocal];
	}
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	NSString * activationStateData = [_sdk.session.serializedState base64EncodedStringWithOptions:0];
	NSUserDefaults * defaults = [NSUserDefaults standardUserDefaults];
	[defaults setObject:auth.usePassword forKey:s_PossessionFactorKey];
	[defaults setObject:activationData.activationId forKey:s_ActivationIdKey];
	[defaults setObject:activationStateData forKey:s_StateDataKey];
	[defaults synchronize];
	
	PA2ActivationStatus * status = [self fetchActivationStatus];
	XCTAssertTrue(status.state == PA2ActivationState_Active);
	
	NSLog(@"=======================================================================");
	NSLog(@"Upgrade params (for old SDK step):");
	NSLog(@"  - password    %@", auth.usePassword);
	NSLog(@"  - act-id      %@", activationData.activationId);
    NSLog(@"  - act-data    %@", activationStateData);
	NSLog(@"=======================================================================");
}

- (void) validateUpgrade
{
	NSUserDefaults * defaults = [NSUserDefaults standardUserDefaults];
	NSString * password = [defaults stringForKey:s_PossessionFactorKey];
	NSString * activationId = [defaults stringForKey:s_ActivationIdKey];
	NSString * activationStateData = [defaults stringForKey:s_StateDataKey];
	
	if (!password || !activationId || !activationStateData) {
		XCTFail(@"Missing password or activation-id from previous activation creation.");
		return;
	}
	
	BOOL hasActivation = [_sdk hasValidActivation];
	if (hasActivation) {
		NSLog(@"WARNING: There's some valid activation, removing it locally.");
		[_sdk removeActivationLocal];
	}
	NSData * stateData = [[NSData alloc] initWithBase64EncodedString:activationStateData options:0];
	if (![_sdk.session deserializeState: stateData]) {
		XCTFail(@"Failed to restore state.");
		return;
	}
	if (![_sdk hasValidActivation]) {
		XCTFail(@"There's no activation after restore.");
		return;
	}
	if (![_sdk.activationIdentifier isEqualToString:activationId]) {
		XCTFail(@"Activation ID is different in serialized status blob.");
		return;
	}
	
	NSLog(@"=======================================================================");
	NSLog(@"Upgrade params (for new SDK step):");
	NSLog(@"  - password %@", password);
	NSLog(@"  - act-id   %@", activationId);
	NSLog(@"=======================================================================");
	
	BOOL result = [self checkForPassword:password];
	XCTAssertFalse(result);
	
	PA2ActivationStatus * status = [self fetchActivationStatus];
	XCTAssertTrue(status.state == PA2ActivationState_Active);
	
	result = [self checkForPassword:password];
	XCTAssertTrue(result);
	
	status = [self fetchActivationStatus];
	XCTAssertTrue(status.state == PA2ActivationState_Active);
	
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.usePassword = password;
	
	NSError * error = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[_sdk removeActivationWithAuthentication:auth callback:^(NSError * _Nullable error) {
			[waiting reportCompletion:error];
		}];
	}];
	XCTAssertNil(error);
	
	[defaults removeObjectForKey:s_StateDataKey];
	[defaults removeObjectForKey:s_ActivationIdKey];
	[defaults removeObjectForKey:s_PossessionFactorKey];
	[defaults synchronize];
}

@end
