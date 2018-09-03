/**
 * Copyright 2017 Wultra s.r.o.
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
#import "FakePowerAuthTokenStore.h"

#import "PowerAuth2.h"

/**
 The `PowerAuthTokenTests` test class is similar to `PowerAuthSDKTests`
 but it's specialized for testing token-related code.
 
 */
@interface PowerAuthTokenTests : XCTestCase
@end

@implementation PowerAuthTokenTests
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
- (PA2ActivationStatus*) fetchActivationStatus
{
	BOOL taskShouldWork = [_sdk hasValidActivation];
	
	__block NSDictionary * activationStatusCustomObject = nil;
	__block NSError * fetchError = nil;
	PA2ActivationStatus * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Start a fetch task.
		PA2OperationTask * task = [_sdk fetchActivationStatusWithCallback:^(PA2ActivationStatus * status, NSDictionary * customObject, NSError * error) {
			activationStatusCustomObject = customObject;
			fetchError = error;
			[waiting reportCompletion:status];
		}];
		// Test whether the task should work.
		// Typically, if activation is not completed, then the asynchronous task is not started, but is reported
		// as cancelled.
		if (taskShouldWork) {
			XCTAssertFalse([task isCancelled]);
		} else {
			XCTAssertTrue([task isCancelled]);
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
		PA2OperationTask * task = [_sdk validatePasswordCorrect:password callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertFalse([task isCancelled]);
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
		PA2OperationTask * task = [_sdk createActivationWithName:activationName activationCode:activationCode callback:^(PA2ActivationResult * result, NSError * error) {
			activationFingerprint = result.activationFingerprint;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should not be cancelled
		XCTAssertFalse([task isCancelled]);
		
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
	XCTAssertTrue(activationStatus.state == PA2ActivationState_OTP_Used);
	
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

#pragma mark - Helper methods

- (NSDictionary*) parseTokenHeaderValue:(NSString*)headerValue
{
	__block BOOL error = NO;
	NSString * magic = @"PowerAuth ";
	NSMutableDictionary * result = [NSMutableDictionary dictionary];
	[[headerValue componentsSeparatedByString:@", "] enumerateObjectsUsingBlock:^(NSString * keyValue, NSUInteger idx, BOOL * stop) {
		if ([keyValue hasPrefix:magic]) {
			keyValue = [keyValue substringFromIndex:magic.length];
			if (idx != 0) {
				error = *stop = YES; return;
			}
		}
		NSRange equalRange = [keyValue rangeOfString:@"="];
		if (equalRange.location == NSNotFound) {
			XCTFail(@"Unknown component: %@", keyValue);
			error = *stop = YES; return;
		}
		NSString * key = [keyValue substringToIndex:equalRange.location];
		NSString * value = [keyValue substringFromIndex:equalRange.location + 1];
		if (![value hasPrefix:@"\""] || ![value hasSuffix:@"\""]) {
			XCTFail(@"Value is not closed in parenthesis: %@", key);
			error = *stop = YES; return;
		}
		result[key] = [value substringWithRange:NSMakeRange(1, value.length-2)];
	}];
	if (!error) {
		error = ![result[@"version"] isEqualToString:@"2.1"];
		XCTAssertFalse(error, @"Unknown PA Token version");
	}
	return error ? nil : result;
}

- (BOOL) validateTokenHeader:(PA2AuthorizationHttpHeader*)header
				activationId:(NSString*)activationId
			  expectedResult:(BOOL)expectedResult
{
	NSDictionary * parsedHeader = [self parseTokenHeaderValue:header.value];
	XCTAssertNotNil(parsedHeader);
	PATSTokenValidationRequest * validationRequest = [[PATSTokenValidationRequest alloc] init];
	validationRequest.tokenIdentifier 	= parsedHeader[@"token_id"];
	validationRequest.tokenDigest 		= parsedHeader[@"token_digest"];
	validationRequest.nonce 			= parsedHeader[@"nonce"];
	validationRequest.timestamp 		= parsedHeader[@"timestamp"];
	PATSTokenValidationResponse * validationResponse = [_testServerApi validateTokenRequest:validationRequest];
	XCTAssertTrue(validationResponse.tokenValid == expectedResult);
	if (expectedResult) {
		XCTAssertTrue([validationResponse.activationId isEqualToString:activationId]);
		XCTAssertTrue([validationResponse.applicationId isEqualToString:_testServerApi.appDetail.applicationId]);
	}
	return validationResponse.tokenValid;
}

#pragma mark - Tests

- (void) runTestsForTokenStore:(id<PowerAuthTokenStore>)tokenStore
					activation:(NSArray*)activation
{
	XCTAssertTrue(activation.count >= 2);
	
	PATSInitActivationResponse * activationData = activation[0];
	//PowerAuthAuthentication * auth = activation[1];
	
	XCTAssertTrue(tokenStore.canRequestForAccessToken);
	
	// Create first token...
	PowerAuthAuthentication * possession = [[PowerAuthAuthentication alloc] init];
	possession.usePossession = YES;
	
	PowerAuthToken * preciousToken = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[tokenStore requestAccessTokenWithName:@"MyPreciousToken" authentication:possession completion:^(PowerAuthToken * token, NSError * error) {
			[waiting reportCompletion:token];
		}];
	}];
	XCTAssertNotNil(preciousToken);
	XCTAssertTrue([preciousToken.tokenName isEqualToString:@"MyPreciousToken"]);
	// Create second token with the same name... This tests whether PowerAuthToken works correctly with internal private data.
	PowerAuthToken * anotherToken = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[tokenStore requestAccessTokenWithName:@"MyPreciousToken" authentication:possession completion:^(PowerAuthToken * token, NSError * error) {
			[waiting reportCompletion:token];
		}];
	}];
	XCTAssertNotNil(anotherToken);
	XCTAssertTrue([preciousToken isEqualToToken:anotherToken]);
	
	// OK, sanity tests passed, now it's time to generate a header...
	PA2AuthorizationHttpHeader * header = [preciousToken generateHeader];
	BOOL result = [self validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
	XCTAssertTrue(result);
	
	header = [anotherToken generateHeader];
	result = [self validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
	XCTAssertTrue(result);

	// Remove token
	BOOL tokenRemoved = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[tokenStore removeAccessTokenWithName:@"MyPreciousToken" completion:^(BOOL removed, NSError * _Nullable error) {
			[waiting reportCompletion:@(removed)];
		}];
	}] boolValue];
	XCTAssertTrue(tokenRemoved);
}

- (void) testTokens_WithFakeTokenStore
{
	CHECK_TEST_CONFIG();
	
	//
	// The purpose of this test is to validate whether our SOAP API for token creation and validation
	// is correct. The only mobile part tested in this routine is our ECIES encryptor, because it's used
	// internally in the test server implementation.
	//
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	PATSInitActivationResponse * activationData = activation[0];
	
	FakePowerAuthTokenStore * tokenStore = [[FakePowerAuthTokenStore alloc] initWithTestServer:_testServerApi activationId:activationData.activationId];
	[self runTestsForTokenStore:tokenStore activation:activation];
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testTokens_WithRealTokenStore
{
	CHECK_TEST_CONFIG();
	
	//
	// The purpose of this test is to validate whether token store produced in PowerAuthSDK
	// works correctly. We're using the same battery of tests than
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	PATSInitActivationResponse * activationData = activation[0];
	[self runTestsForTokenStore:_sdk.tokenStore activation:activation];
	
	// Cleanup
	[self removeLastActivation:activationData];
	
	// After cleanup, we can check whether the store can still sign headers
	[_sdk removeActivationLocal];
	XCTAssertFalse(_sdk.tokenStore.canRequestForAccessToken);
}

@end
