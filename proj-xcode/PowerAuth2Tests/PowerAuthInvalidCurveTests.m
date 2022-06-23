/**
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
#import "PowerAuthTestServerAPI.h"
#import "PowerAuthTestServerConfig.h"
#import "AsyncHelper.h"

@import PowerAuth2;
@import PowerAuthCore;

@interface PowerAuthInvalidCurveTests: XCTestCase
@end

@implementation PowerAuthInvalidCurveTests
{
	PowerAuthTestServerConfig * _testServerConfig;	// Loaded config
	PowerAuthTestServerAPI * _testServerApi;		// SOAP connection
	PowerAuthConfiguration * _config;				// Default SDK config
	PowerAuthSDK * _sdk;							// Default SDK instance
	
	BOOL _hasConfig;
	BOOL _invalidConfig;
}

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
	
	// Print report
	NSLog(@"=======================================================================");
	NSLog(@"The integration tests will run against following servers:");
	NSLog(@"    REST API Server: %@", _testServerConfig.restApiUrl);
	NSLog(@"    SOAP API Server: %@", _testServerConfig.soapApiUrl);
	NSLog(@"               User: %@", _testServerConfig.userIdentifier);
	NSLog(@"=======================================================================");
	
	return YES;
}

/**
 Performs one-time initialization for all unit tests. The result of calling this method is
 pepared all i-vars with runtime variables, like _sdk, _soapApiURL, etc...
 */
- (void) runOnceForAllTests
{
	PowerAuthLogSetEnabled(YES);
	
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
		_config.instanceId = @"IntegrationTests";
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
		[_sdk removeActivationLocal];
		
		result = _sdk != nil;
		result = result && [_sdk hasPendingActivation] == NO;
		
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
	NSArray<NSString*> * veryCleverPasswords = @[ @"supersecure", @"nbusr123", @"8520", @"pa55w0rd" ];
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = NO;		// There's no human being involved in the automatic test :)
	auth.usePassword = veryCleverPasswords[arc4random_uniform((uint32_t)veryCleverPasswords.count)];
	return auth;
}

/**
 Returns an activation status object. May return nil if status is not available yet, which is also valid operation.
 */
- (PowerAuthActivationStatus*) fetchActivationStatus
{
	BOOL taskShouldWork = [_sdk hasValidActivation];
	
	__block NSDictionary * activationStatusCustomObject = nil;
	__block NSError * fetchError = nil;
	PowerAuthActivationStatus * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Start a fetch task.
		id<PowerAuthOperationTask> task = [_sdk fetchActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error) {
			activationStatusCustomObject = customObject;
			fetchError = error;
			[waiting reportCompletion:status];
		}];
		// Test whether the task should work.
		// Typically, if activation is not completed, then the asynchronous task is not started, but is reported
		// as cancelled.
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
		id<PowerAuthOperationTask> task = [_sdk validatePasswordCorrect:password callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	return result;
}

/**
 Converts factors from auth object to string.
 */
- (NSString*) authToString:(PowerAuthAuthentication*)auth
{
	NSMutableArray * components = [NSMutableArray arrayWithCapacity:3];
	if (auth.usePossession) {
		[components addObject:@"POSSESSION"];
	}
	if (auth.usePassword) {
		[components addObject:@"KNOWLEDGE"];
	}
	if (auth.useBiometry) {
		[components addObject:@"BIOMETRY"];
	}
	return [components componentsJoinedByString:@"_"];
}

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
	NSArray * preliminaryResult = nil;
	
	__block NSString * activationFingerprint = nil;
	
	// 2) CLIENT: Start activation on client's side
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		NSString * activationName = _testServerConfig.userActivationName;
		id<PowerAuthOperationTask> task = [_sdk createActivationWithName:activationName activationCode:activationCode callback:^(PowerAuthActivationResult * result, NSError * error) {
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
	PowerAuthActivationStatus * activationStatus = [self fetchActivationStatus];
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
	
	if (_testServerConfig.isServerAutoCommit) {
		// 3.1) CLIENT: Fetch status again. In this time, the operation should work and return ACTIVE
		activationStatus = [self fetchActivationStatus];
		XCTAssertNotNil(activationStatus);
		XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
	} else {
		// 3.1) CLIENT: Fetch status again. In this time, the operation should work and return PENDING_COMMIT
		activationStatus = [self fetchActivationStatus];
		XCTAssertNotNil(activationStatus);
		XCTAssertTrue(activationStatus.state == PowerAuthActivationState_PendingCommit);
		
		// 4) SERVER: This is the last step of activation. We need to commit an activation on the server side.
		//            This is typically done internally on the server side and depends on activation flow
		//            in concrete internet banking project.
		result = [_testServerApi commitActivation:activationData.activationId];
		XCTAssertTrue(result, @"Server's commit failed");
		CHECK_RESULT_RET(preliminaryResult);
		
		// 5) CLIENT: Fetch status again. Now the state should be active
		activationStatus = [self fetchActivationStatus];
		XCTAssertNotNil(activationStatus);
		XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
	}
	
	// Post activation steps...
	result = [_sdk.session.activationIdentifier isEqualToString:activationData.activationId];
	XCTAssertTrue(result, @"Activation identifier in session is different to identifier generated on the server.");
	CHECK_RESULT_RET(preliminaryResult);
	
	// Now it's time to validate activation status, created on the server
	PATSActivationStatus * serverActivationStatus = [_testServerApi getActivationStatus:activationData.activationId challenge:nil];
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

// Following test needs to be rewritten to standard ECIES.

/*
#pragma mark - Integration tests

- (void) testGetToken_InvalidEphemeralKey
{
	CHECK_TEST_CONFIG()
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	PATSInitActivationResponse * activationData = activation[0];
	
	[self doGetToken_InvalidEphemeralKey: activationData];
	
	// Cleanup
	[self removeLastActivation:activationData];
	
	// After cleanup, we can check whether the store can still sign headers
	[_sdk removeActivationLocal];
	
}

- (void) doGetToken_InvalidEphemeralKey:(PATSInitActivationResponse*)activationData
{
	NSDictionary * requestObjects =
	@{
	  @"requestObject": @{ @"ephemeralPublicKey" : @"ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/" }
	 };
	NSData * requestData = [NSJSONSerialization dataWithJSONObject:requestObjects options:0 error:NULL];
	XCTAssertNotNil(requestData);
	// Simulate 'pa/token/create' call
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	
	NSError * error = nil;
	PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:@"POST" uriId:@"/pa/token/create" body:requestData error:&error];
	if (!header || error) {
		XCTFail(@"Cannot sign manually constructed request: Error: %@", error);
		return;
	}
	
	PA2Client * client = [[PA2Client alloc] init];
	NSURL * url = [NSURL URLWithString:[_testServerConfig.restApiUrl stringByAppendingString:@"/pa/token/create"]];
	NSDictionary * headers = @{ header.key : header.value };
	__block NSData * resp_data = nil;
	BOOL success = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[client postToUrl:url data:requestData headers:headers completion:^(NSData * data, NSURLResponse * response, NSError * error) {
			if (((NSHTTPURLResponse*)response).statusCode == 200) {
				resp_data = data;
				[waiting reportCompletion:@YES];
			} else {
				[waiting reportCompletion:@NO];
			}
		}];
	}] boolValue];

	XCTAssertFalse(success, @"Request should not finish with success.");
}
*/

@end
