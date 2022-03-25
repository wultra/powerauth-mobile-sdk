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

/**
 The purpose of `PowerAuthSDKTests` is to run a series of integration tests where the
 high level `PowerAuthSDK` class is a primary test subject. All integration tests
 needs a running server as a counterpart and therefore are by-default disabled for all
 main development schemas ("PA2_Release", "PA2_Debug"). To run this test, you
 need to switch to "PA2_IntegrationTests" scheme and create a configuration.
 Check 'TestConfig/Readme.md' for details.
 */
@interface PowerAuthSDKTests : XCTestCase
@end

@implementation PowerAuthSDKTests
{
	PowerAuthTestServerConfig * _testServerConfig;	// Loaded config
	PowerAuthTestServerAPI * _testServerApi;		// SOAP connection
	PowerAuthConfiguration * _config;				// Default SDK config
	PowerAuthSDK * _sdk;							// Default SDK instance
	
	BOOL _hasConfig;
	BOOL _invalidConfig;
}

static NSString * PA_Ver = @"3.1";

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
 Returns @[ signature, nonceB64 ] if succeeded or nil in case of error.
 Doesn't throw test exception on errors.
 */
- (NSArray*) calculateOfflineSignature:(NSData*)data
								 uriId:(NSString*)uriId
								  auth:(PowerAuthAuthentication*)auth
{
	NSError * error = nil;
	NSString * nonce = @"QVZlcnlDbGV2ZXJOb25jZQ==";
	NSString * signature = [_sdk offlineSignatureWithAuthentication:auth uriId:uriId body:data nonce:nonce error:&error];
	if (signature && !error) {
		return @[ signature, nonce ];
	}
	return nil;
}


/**
 Returns @[ signature, nonceB64 ] if succeeded or nil in case of error.
 Throws test exception only when header contains invalid data (e.g. parser fail process the header)
 */
- (NSArray*) calculateOnlineSignature:(NSData*)data
							   method:(NSString*)method
								uriId:(NSString*)uriId
								 auth:(PowerAuthAuthentication*)auth
{
	NSError * error = nil;
	PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:method uriId:uriId body:data error:&error];
	if (header && header.value && !error) {
		NSDictionary * parsedHeader = [self parseSignatureHeaderValue:header.value];
		NSString * nonce     = parsedHeader[@"pa_nonce"];
		NSString * signature = parsedHeader[@"pa_signature"];
		if (nonce && signature) {
			return @[ signature, nonce];
		}
	}
	return nil;
}


/*
 Returns dictionary created from "X-PowerAuth-Authorization" header's value.
 */
- (NSDictionary*) parseSignatureHeaderValue:(NSString*)headerValue
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
		if (![key hasPrefix:@"pa_"]) {
			XCTFail(@"Unknown key: %@", key);
			error = *stop = YES; return;
		}
		result[key] = [value substringWithRange:NSMakeRange(1, value.length-2)];
	}];
	if (!error) {
		error = ![result[@"pa_version"] isEqualToString:PA_Ver];
		XCTAssertFalse(error, @"Unknown PA version");
	}
	return error ? nil : result;
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


/**
 Makes full test against server with signature verification. You can set cripple parameter to following bitmask:
	0x0001 - will cripple auth object (e.g. change factor)
	0x0010 - will cripple data
	0x0100 - will cripple method string
	0x1000 - will cripple uriId string
 */
- (BOOL) validateSignature:(PowerAuthAuthentication*)auth data:(NSData*)data method:(NSString*)method uriId:(NSString*)uriId
					online:(BOOL)online
				   cripple:(NSInteger)cripple
{
	// data for local calculation
	PowerAuthAuthentication * local_auth = [auth copy];
	NSMutableData * local_data = [data mutableCopy];
	NSString * local_method = method;
	NSString * local_uriId = uriId;
	
	if (cripple & 0x0001) {
		// cripple auth object
		if (local_auth.usePassword) {
			local_auth.usePassword = nil;
		} else {
			local_auth.usePassword = @"TotallyWrongPassword";
		}
		if (local_auth.usePassword == nil && !local_auth.usePossession) {
			local_auth.usePossession = YES;
		}
	}
	if (cripple & 0x0010) {
		// cripple data
		[local_data appendData:[@"- is crippled" dataUsingEncoding:NSUTF8StringEncoding]];
	}
	if (cripple & 0x0100) {
		// cripple method
		if ([local_method isEqualToString:@"POST"]) {
			local_method = @"GET";
		} else {
			local_method = @"POST";
		}
	}
	if (cripple & 0x1000) {
		// cripple uri identifier
		local_uriId = [local_uriId stringByAppendingString:@"/is/crippled"];
	}
	
	// Now locally calculate signature & nonce
	NSArray * local_sig_nonce;
	NSString * signature_version = PA_Ver;
	if (online) {
		local_sig_nonce = [self calculateOnlineSignature:local_data method:local_method uriId:local_uriId auth:local_auth];
	} else {
		local_sig_nonce = [self calculateOfflineSignature:local_data uriId:local_uriId auth:local_auth];
	}
	if (!local_sig_nonce) {
		XCTAssertNotNil(local_sig_nonce, @"Wrong test code. The signature must be calculated here.");
		return NO;
	}
	NSString * local_signature = local_sig_nonce[0];
	NSString * local_nonce = local_sig_nonce[1];
	
	// Verify result on the server
	NSString * normalized_data = [_testServerApi normalizeDataForSignatureWithMethod:method uriId:uriId nonce:local_nonce data:data];
	PATSVerifySignatureResponse * response;
	if (online) {
		response = [_testServerApi verifySignature:_sdk.activationIdentifier
											   data:normalized_data
										  signature:local_signature
									  signatureType:[self authToString:auth]
								  signatureVersion:signature_version];
		XCTAssertNotNil(response, @"Online response must be received");
	} else {
		response = [_testServerApi verifyOfflineSignature:_sdk.activationIdentifier
													 data:normalized_data
												signature:local_signature
											allowBiometry:NO];
		XCTAssertNotNil(response, @"Offline response must be received");
	}
	BOOL result = (response != nil) && (response.signatureValid == (cripple == 0));
	if (!result) {
		if (cripple == 0) {
			XCTAssertTrue(response.signatureValid, @"Signature should be valid");
		} else {
			XCTAssertFalse(response.signatureValid, @"Signature should not be valid");
		}
	}
	return result;
}

- (NSData*) sessionCoreSerializedState
{
	return [_sdk.sessionProvider readTaskWithSession:^id _Nullable(PowerAuthCoreSession * _Nonnull session) {
		return [session serializedState];
	}];
}

- (BOOL) sessionCoreDeserializeState:(NSData*)state
{
	return  [_sdk.sessionProvider writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * _Nonnull session) {
		return [session deserializeState:state];
	}];
}

#pragma mark - Integration tests

#pragma mark - Activation

/**
 Returns @[PATSInitActivationResponse, PowerAuthAuthentication, PowerAuthActivationResult, @(BOOL)] with activation data, authentication object,
 and result of activation. You can configure whether the activation can use optional signature during the activation
 and whether the activation should be removed automatically after the creation.
 */
- (NSArray*) createActivation:(BOOL)useSignature
				activationOtp:(NSString*)activationOtp
				  removeAfter:(BOOL)removeAfter
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
	XCTAssertNil(_sdk.activationIdentifier);
	XCTAssertNil(_sdk.activationFingerprint);
	
	// 1) SERVER: initialize an activation on server (this is typically implemented in the internet banking application)
	PATSActivationOtpValidationEnum otpValidation = activationOtp != nil ? PATSActivationOtpValidation_ON_KEY_EXCHANGE : PATSActivationOtpValidation_NONE;
	PATSInitActivationResponse * activationData = [_testServerApi initializeActivation:_testServerConfig.userIdentifier
																		 otpValidation:otpValidation
																				   otp:activationOtp];
	NSString * activationCode = useSignature ? [activationData activationCodeWithSignature] : [activationData activationCodeWithoutSignature];
	NSArray * preliminaryResult = nil;
	
	__block PowerAuthActivationResult * activationResult = nil;
	
	// 2) CLIENT: Start activation on client's side
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		NSString * activationName = _testServerConfig.userActivationName;
		PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:activationCode name:activationName error:nil];
		if (activationOtp) {
			[activation withAdditionalActivationOtp:activationOtp];
		}
		id<PowerAuthOperationTask> task = [_sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
			activationResult = result;
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
	XCTAssertTrue([activationData.activationId isEqualToString:_sdk.activationIdentifier]);
	NSString * activationFingerprintBeforeCommit = _sdk.activationFingerprint;
	XCTAssertNotNil(activationFingerprintBeforeCommit);
	
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
	
	// 3.1) CLIENT: Fetch status again. In this time, the operation should work and return status depending
	//              on whether activation OTP was used.
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	if (activationOtp != nil) {
		// If activation OTP was used for the activation, then the activation is ACTIVE right now.
		XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
	} else {
		XCTAssertTrue(activationStatus.state == PowerAuthActivationState_PendingCommit);
		// 4) SERVER: This is the last step of activation. We need to commit an activation on the server side.
		//            This is typically done internally on the server side and depends on activation flow
		//            in concrete internet banking project.
		result = [_testServerApi commitActivation:activationData.activationId];
		XCTAssertTrue(result, @"Server's commit failed");
		CHECK_RESULT_RET(preliminaryResult);
	}
	
	// 5) CLIENT: Fetch status again. Now the state should be active
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
	
	// Post activation steps...
	result = [_sdk.activationIdentifier isEqualToString:activationData.activationId];
	XCTAssertTrue(result, @"Activation identifier in session is different to identifier generated on the server.");
	CHECK_RESULT_RET(preliminaryResult);
	
	// Now it's time to validate activation status, created on the server
	PATSActivationStatus * serverActivationStatus = [_testServerApi getActivationStatus:activationData.activationId challenge:nil];
	result = serverActivationStatus != nil;
	CHECK_RESULT_RET(preliminaryResult);
	XCTAssertTrue([serverActivationStatus.activationName isEqualToString:_testServerConfig.userActivationName]);
	// Test whether the device's public key fingerprint is equal on server and client.
	XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationResult.activationFingerprint]);
	XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:_sdk.activationFingerprint]);
	XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationFingerprintBeforeCommit]);
	
	// This is just a cleanup. If remove will fail, then we don't report an error
	if (removeAfter || !result) {
		if (!result) {
			NSLog(@"We're removing activation due to fact, that session creation failed.");
		}
		[self removeLastActivation:activationData];
	}
	return @[activationData, auth, activationResult, @YES];
}

- (NSArray*) createActivation:(BOOL)useSignature removeAfter:(BOOL)removeAfter
{
	return [self createActivation:useSignature activationOtp:nil removeAfter:removeAfter];
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
		activationId = _sdk.activationIdentifier;
	}
	if (!activationId) {
		activationId = _sdk.activationIdentifier;
	}
	if (!activationId) {
		NSLog(@"WARNING: Unable to remove activation. This is not an error, but you'll see a lot of unfinished activations.");
	}
	[_testServerApi removeActivation:activationId];
}


/*
 In positive scenarios we're testing situations, when everything looks fine.
 */
#pragma mark - Tests: Positive scenarios


- (void) testCreateActivationWithSignature
{
	CHECK_TEST_CONFIG();
	
	NSArray * activation = [self createActivation:YES removeAfter:YES];
	XCTAssertTrue([activation.lastObject boolValue]);
}


- (void) testCreateActivationWithhoutSignature
{
	CHECK_TEST_CONFIG();
	
	NSArray * activation = [self createActivation:NO removeAfter:YES];
	XCTAssertTrue([activation.lastObject boolValue]);
}

- (void) testCreateActivationWithOtpAndSignature
{
	CHECK_TEST_CONFIG();
	
	NSArray * activation = [self createActivation:YES
									activationOtp:@"12345"
									  removeAfter:YES];
	XCTAssertTrue([activation.lastObject boolValue]);
}

- (void) testRemoveActivation
{
	CHECK_TEST_CONFIG();
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];

	// Remove activation from the server
	NSError * removeError = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk removeActivationWithAuthentication:auth callback:^(NSError * error) {
			[waiting reportCompletion:error];
		}];
		XCTAssertNotNil(task);
	}];
	XCTAssertNil(removeError);
	XCTAssertNil(_sdk.activationIdentifier);
	
	// Cleanup, only if the SDK remove did fail
	if (removeError) {
		[self removeLastActivation:activationData];
	}
}

- (void) testPasswordCorrect
{
	CHECK_TEST_CONFIG();
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	// 1) At first, use invalid password
	result = [self checkForPassword:@"MustBeWring"];
	XCTAssertFalse(result);	// if YES then something is VERY wrong. The wrong password passed the test.
	
	// 2) Now use a valid password
	result = [self checkForPassword:auth.usePassword];
	XCTAssertTrue(result);	// if NO then a valid password did not pass the test.
	
	// Cleanup
	[self removeLastActivation:activationData];
}


- (void) testChangePassword
{
	CHECK_TEST_CONFIG();
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	NSString * newPassword = @"nbusr321";
	
	// 1) At first, change password
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk changePasswordFrom:auth.usePassword to:newPassword callback:^(NSError * _Nullable error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should not be cancelled
		XCTAssertNotNil(task);
	}] boolValue];
	XCTAssertTrue(result);
	
	// 2) Now validate that new password
	result = [self checkForPassword:newPassword];
	XCTAssertTrue(result);
	
	// Cleanup
	[self removeLastActivation:activationData];
}



- (void) testValidateSignature
{
	CHECK_TEST_CONFIG();
	
	//
	// This test validates functions for PA signature calculations.
	//
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	PowerAuthAuthentication * auth_possession = [[PowerAuthAuthentication alloc] init];
	auth_possession.usePossession = YES;
	
	PowerAuthAuthentication * auth_possession_knowledge = [[PowerAuthAuthentication alloc] init];
	auth_possession_knowledge.usePossession = YES;
	auth_possession_knowledge.usePassword = auth.usePassword;
	
	//
	// Online & offline signatures (calculated as http auth header)
	//
	for (int i = 1; i <= 2; i++)
	{
		BOOL online_mode = i == 1;
		// Offline signature contains a
		NSData * data = online_mode
							? [@"hello online world" dataUsingEncoding:NSUTF8StringEncoding]
							: [[NSData alloc] initWithBase64EncodedString:@"zYnF8edfgfgT2TcZjupjppBHoUJGjONkk6H+eThIsi0=" options:0] ;
		// Positive
		if (online_mode) {
			result = [self validateSignature:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0];
			XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
		}
		result = [self validateSignature:auth_possession_knowledge data:data method:online_mode ? @"GET" : @"POST" uriId:@"/hello/hacker" online:online_mode cripple:0];
		XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
		// Negative
		result = [self validateSignature:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0x0001];
		XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
		result = [self validateSignature:auth_possession_knowledge data:data method:@"GET" uriId:@"/hello/hacker" online:online_mode cripple:0x0010];
		XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
		result = [self validateSignature:auth_possession data:data method:@"GET" uriId:@"/hello/from/test" online:online_mode cripple:0x0100];
		XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
		result = [self validateSignature:auth_possession_knowledge data:data method:@"POST" uriId:@"/hello/from/test" online:online_mode cripple:0x1000];
		XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
	}
	
	// Do more valid signatures. Count is important, due to fact that we have 8-bit local counter sice V3.1
	for (int i = 1; i < 264; i++) {
		result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			id<PowerAuthOperationTask> task = [_sdk validatePasswordCorrect:auth.usePassword callback:^(NSError * error) {
				[waiting reportCompletion:@(error == nil)];
			}];
			XCTAssertNotNil(task);
		}] boolValue];
		XCTAssertTrue(result);
		if ((i & 0x3f) == 1) {
			XCTAssertTrue(PowerAuthActivationState_Active == [self fetchActivationStatus].state);
		}
	}
	// One last status check
	XCTAssertTrue(PowerAuthActivationState_Active == [self fetchActivationStatus].state);
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testVerifyServerSignedData
{
	CHECK_TEST_CONFIG();
	
	//
	// This test checks whether SDK can verify data signed by server's master key
	//
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	PATSOfflineSignaturePayload * payload;
	{
		// Verify data signed with master key (non-personalized)
		NSString * dataForSigning = @"All your money are belong to us!";
		payload = [_testServerApi createNonPersonalizedOfflineSignaturePayload:activationData.applicationId data:dataForSigning];
		XCTAssertNotNil(payload);
		XCTAssertTrue([payload.parsedData isEqualToString:dataForSigning]);
		XCTAssertTrue([payload.parsedSigningKey isEqualToString:@"0"]);
		
		NSData * signedData = [payload.parsedSignedData dataUsingEncoding:NSUTF8StringEncoding];
		result = [_sdk verifyServerSignedData:signedData signature:payload.parsedSignature masterKey:YES];
		XCTAssertTrue(result, @"Wrong signature calculation, or server did not sign this data");
	}
	{
		// Verify data signed with server key (personalized)
		NSString * dataForSigning = @"All your money are belong to us!";
		payload = [_testServerApi createPersonalizedOfflineSignaturePayload:activationData.activationId data:dataForSigning];
		XCTAssertNotNil(payload);
		XCTAssertTrue([payload.parsedData isEqualToString:dataForSigning]);
		XCTAssertTrue([payload.parsedSigningKey isEqualToString:@"1"]);
		
		NSData * signedData = [payload.parsedSignedData dataUsingEncoding:NSUTF8StringEncoding];
		result = [_sdk verifyServerSignedData:signedData signature:payload.parsedSignature masterKey:NO];
		XCTAssertTrue(result, @"Wrong signature calculation, or server did not sign this data");
	}
	
	// Well, we have a data for offline signature, so let's try to verify it.
	NSString * uriId = @"/operation/authorize/offline";
	NSData * body = [payload.parsedData dataUsingEncoding:NSUTF8StringEncoding];
	NSString * nonce = payload.nonce;

	PowerAuthAuthentication * sign_auth = [[PowerAuthAuthentication alloc] init];
	sign_auth.usePassword = auth.usePassword;
	sign_auth.usePossession = YES;
	NSString * local_signature = [_sdk offlineSignatureWithAuthentication:sign_auth uriId:uriId body:body nonce:nonce error:NULL];
	XCTAssertNotNil(local_signature);

	NSString * normalized_data = [_testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:uriId nonce:nonce data:body];
	XCTAssertNotNil(normalized_data);
	PATSVerifySignatureResponse * response = [_testServerApi verifyOfflineSignature:activationData.activationId data:normalized_data signature:local_signature allowBiometry:NO];
	XCTAssertTrue(response.signatureValid);
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testSignDataWithDevicePrivateKey
{
	CHECK_TEST_CONFIG();
	
	//
	// This test checks data signing with device's private key.
	//
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	NSData * dataForSigning = [@"This is a very sensitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];

	// 1) At first, calculate signature
	__block NSData * resultSignature = nil;
	__block NSError * resultError = nil;
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk signDataWithDevicePrivateKey:auth data:dataForSigning callback:^(NSData * signature, NSError * error) {
			resultSignature = signature;
			resultError = error;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should not be cancelled
		XCTAssertNotNil(task);
	}] boolValue];
	XCTAssertTrue(result);
	
	// 2) Verify signature on the server
	if (result) {
		result = [_testServerApi verifyECDSASignature:activationData.activationId data:dataForSigning signature:resultSignature];
		XCTAssertTrue(result);
	}
	
	// Cleanup
	[self removeLastActivation:activationData];
}


- (void) testActivationStatus
{
	CHECK_TEST_CONFIG();
	
	//
	// This test checks whether SDK correctly maps server's activation status.
	// We're testing "ACTIVE", "BLOCKED", "REMOVED" states only, because other
	// states are automatically validated during the activation creation.
	//
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	
	PowerAuthActivationStatus * status;
	PATSSimpleActivationStatus * serverStatus;
	
	// 1) Initial state is "active"
	status = [self fetchActivationStatus];
	XCTAssertEqual(status.state, PowerAuthActivationState_Active);
	
	// 2) Block activation & fetch status
	serverStatus = [_testServerApi blockActivation:activationData.activationId];
	XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_BLOCKED);
	
	status = [self fetchActivationStatus];
	XCTAssertEqual(status.state, PowerAuthActivationState_Blocked);

	// 3) Unblock activation & fetch status
	serverStatus = [_testServerApi unblockActivation:activationData.activationId];
	XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_ACTIVE);
	
	status = [self fetchActivationStatus];
	XCTAssertEqual(status.state, PowerAuthActivationState_Active);
	
	// 4) Remove activation (which is also cleanup)
	[self removeLastActivation:activationData];
	
	// 5) Fetch last status
	status = [self fetchActivationStatus];
	XCTAssertEqual(status.state, PowerAuthActivationState_Removed);
}

- (void) testActivationStatusFailCounters
{
	CHECK_TEST_CONFIG();
	
	//
	// This test checks whether SDK & Server correctly works
	// with fail / max fail counters after data signing.
	//
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	// Correct AUTH with knowledge
	result = [self checkForPassword:auth.usePassword];
	XCTAssertTrue(result);
	PowerAuthActivationStatus * status_after_correct = [self fetchActivationStatus];
	
	// Wrong AUTH with knowledge
	result = [self checkForPassword:@"MustBeWrong"];
	XCTAssertFalse(result);	// result is invalid password
	PowerAuthActivationStatus * status_after_failure = [self fetchActivationStatus];
	XCTAssertTrue(status_after_correct.failCount + 1 == status_after_failure.failCount, @"failCount was not incremented or has wrong value");
	
	// Sign with possession factor
	NSData * data = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];
	PowerAuthAuthentication * just_possession = [[PowerAuthAuthentication alloc] init];
	just_possession.usePossession = YES;
	NSArray * sig_nonce = [self calculateOnlineSignature:data method:@"POST" uriId:@"/hello/world" auth:just_possession];
	XCTAssertNotNil(sig_nonce);
	// Verify on the server (we're using SOAP because vanilla PA REST server doesn't have endpoint signed with possession
	NSString * normalized_data = [_testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/hello/world" nonce:sig_nonce[1] data:data];
	PATSVerifySignatureResponse * response = [_testServerApi verifySignature:activationData.activationId data:normalized_data signature:sig_nonce[0] signatureType:@"POSSESSION" signatureVersion:PA_Ver];
	XCTAssertNotNil(response);
	XCTAssertTrue(response.signatureValid, @"Calculated signature is not valid");

	// Now check status after valid possession signature
	PowerAuthActivationStatus * status_after_possession = [self fetchActivationStatus];
	XCTAssertTrue(status_after_possession.failCount == status_after_failure.failCount, @"failCount should not change after valid possession factor");
	
	// Now try valid password
	// Fail attempt
	result = [self checkForPassword:auth.usePassword];
	XCTAssertTrue(result);
	status_after_correct = [self fetchActivationStatus];
	XCTAssertNotNil(status_after_correct);
	XCTAssertTrue(status_after_correct.failCount == 0, "Fail counter was not reset to zero");
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testActivationStatusMaxFailAttempts
{
	CHECK_TEST_CONFIG();
	
	//
	// This test validates maximum number failed of auth. attempts
	//
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	// Correct AUTH with knowledge
	result = [self checkForPassword:auth.usePassword];
	XCTAssertTrue(result);
	PowerAuthActivationStatus * status_after_correct = [self fetchActivationStatus];
	PowerAuthActivationStatus * after = status_after_correct;
	
	XCTAssertTrue(status_after_correct.failCount == 0);
	UInt32 count = status_after_correct.maxFailCount;
	for (UInt32 i = 1; i <= count; i++) {
		PowerAuthActivationStatus * before = after;
		XCTAssertNotNil(before);
		result = [self checkForPassword:@"MustBeWrong"];
		XCTAssertFalse(result);	// result is invalid password
		after = [self fetchActivationStatus];
		XCTAssertNotNil(after);
		XCTAssertTrue(before.failCount + 1 == after.failCount, @"failCount was not incremented");
		if (i < count) {
			// still active
			XCTAssertTrue(after.state == PowerAuthActivationState_Active, @"Activation should be active");
		} else {
			// blocked
			XCTAssertTrue(after.state == PowerAuthActivationState_Blocked, @"Activation should be blocked");
		}
	}
	
	// Cleanup
	[self removeLastActivation:activationData];
}

#define CTR_LOOKAHEAD 20	// Default constant on the server

- (void) testCounterSync_ClientIsAhead
{
	CHECK_TEST_CONFIG();
	
	//
	// This test validates whether Mobile SDK proactively synchronize counter
	// on the server, when local counter is slightly ahead to server's.
	//
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	PowerAuthActivationStatus * status;
	// Positive
	for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
		// Just calculate signature on the client. This step simulates a network connection failure.
		PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil  error:NULL];
		XCTAssertNotNil(header);
		if ((i % 4) == 0) {
			// Every 4th signature calculation try to get the status
			status = [self fetchActivationStatus];
			XCTAssertNotNil(status);
			// Everything should be OK, because getting the status fires signature validation internally.
			XCTAssertEqual(status.state, PowerAuthActivationState_Active);
		}
	}
	status = [self fetchActivationStatus];
	XCTAssertNotNil(status);
	XCTAssertEqual(status.state, PowerAuthActivationState_Active);
	
	// Negative
	// Now try to calculate too many signatures that server will never catch
	for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
		// Just calculate signature on the client. This step simulates a network connection failure.
		PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil  error:NULL];
		XCTAssertNotNil(header);
	}
	
	// Now get the status. It should be a deadlocked.
	status = [self fetchActivationStatus];
	XCTAssertNotNil(status);
	XCTAssertEqual(status.state, PowerAuthActivationState_Deadlock);
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testCounterSync_ServerIsAhead
{
	CHECK_TEST_CONFIG();
	
	//
	// This test validates whether Mobile SDK is able to catch
	// server's counter if server is slightly ahead.
	//
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	PowerAuthActivationStatus * status;

	// Positive
	NSData * data_to_sign = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];

	// Just calculate signature on the server.
	// This is a little bit tricky, because we need to calculate a valid signature, to move server's counter forward. To do that,
	// we have to calculate also a local signature, but that moves also local counter forward.
	// To trick the system, we need to keep old persistent data and restore it later.
	NSData * previous_state = [self sessionCoreSerializedState];
	for (int i = 0; i < CTR_LOOKAHEAD/2; i++) {
		NSString * local_signature = [_sdk offlineSignatureWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" error:NULL];
		NSString * normalized_data = [_testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
		PATSVerifySignatureResponse * response = [_testServerApi verifyOfflineSignature:_sdk.activationIdentifier data:normalized_data signature:local_signature allowBiometry:NO];
		XCTAssertNotNil(response, @"Online response must be received");
		XCTAssertTrue(response.signatureValid);
	}
	// Rollback counter to some previous state.
	[self sessionCoreDeserializeState:previous_state];
	// Fetch the status. This should move local counter forward, so the next calculation will succeed.
	status = [self fetchActivationStatus];
	XCTAssertNotNil(status);
	XCTAssertEqual(status.state, PowerAuthActivationState_Active);
	BOOL password_result = [self checkForPassword:auth.usePassword];
	XCTAssertTrue(password_result);
	
	// Negative
	// Now try to calculate too many signatures that client will never catch the server.
	previous_state = [self sessionCoreSerializedState];
	for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
		NSString * local_signature = [_sdk offlineSignatureWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" error:NULL];
		NSString * normalized_data = [_testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
		PATSVerifySignatureResponse * response = [_testServerApi verifyOfflineSignature:_sdk.activationIdentifier data:normalized_data signature:local_signature allowBiometry:NO];
		XCTAssertNotNil(response, @"Online response must be received");
		XCTAssertTrue(response.signatureValid);
	}
	// Rollback counter to some previous state.
	[self sessionCoreDeserializeState:previous_state];
	
	// Now get the status. It should be a deadlocked.
	status = [self fetchActivationStatus];
	XCTAssertNotNil(status);
	XCTAssertEqual(status.state, PowerAuthActivationState_Deadlock);
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testRecoveryCodes
{
	CHECK_TEST_CONFIG()
	
	//
	// This test validates whether the recovery code received in activation can be confirmed.
	// If server supports recovery codes, then such code can be confirmed, but it's already confirmed.
	// Also we can create a new activation with using recovery code and PUK. That operation must remove
	// original activation.
	//
	
	BOOL result;
	NSError * operationError = nil;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	PowerAuthActivationResult * activationResult = activation[2];
	PowerAuthActivationRecoveryData * recoveryData = activationResult.activationRecovery;
	
	if (!recoveryData) {
		XCTAssertFalse([_sdk hasActivationRecoveryData]);
		// Cleanup
		NSLog(@"WARNING: Server doesn't support recovery codes.");
		[self removeLastActivation:activationData];
		return;
	}
	
	// 1. now try to confirm received recovery code
	
	XCTAssertTrue([_sdk hasActivationRecoveryData]);
	
	__block BOOL isAlreadyConfirmed = NO;
	__block NSError * resultError = nil;
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk confirmRecoveryCode:recoveryData.recoveryCode authentication:auth callback:^(BOOL alreadyConfirmed, NSError * _Nullable error) {
			isAlreadyConfirmed = alreadyConfirmed;
			resultError = error;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should be valid
		XCTAssertNotNil(task);
	}] boolValue];
	
	XCTAssertTrue(result);
	XCTAssertTrue(isAlreadyConfirmed);
	
	// 2. Get recovery codes
	
	__block PowerAuthActivationRecoveryData * decryptedRecoveryData = nil;
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk activationRecoveryData:auth callback:^(PowerAuthActivationRecoveryData * _Nullable recoveryData, NSError * _Nullable error) {
			decryptedRecoveryData = recoveryData;
			resultError = error;
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	
	XCTAssertTrue(result);
	XCTAssertTrue([recoveryData.recoveryCode isEqualToString:decryptedRecoveryData.recoveryCode]);
	XCTAssertTrue([recoveryData.puk isEqualToString:decryptedRecoveryData.puk]);
	
	// 3. Now remove a local activation. This simulates that user loose the device.
	
	[_sdk removeActivationLocal];
	
	// 4. Try to create a new activation with recovery code and PUK.
	
	__block PowerAuthActivationResult * newActivation = nil;
	__block NSError * newActivationError = nil;
	
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		NSString * activationName = _testServerConfig.userActivationName;
		id<PowerAuthOperationTask> task = [_sdk createActivationWithName:activationName recoveryCode:recoveryData.recoveryCode puk:recoveryData.puk extras:nil callback:^(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error) {
			newActivation = result;
			newActivationError = error;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should be valid
		XCTAssertNotNil(task);
	}] boolValue];
	
	XCTAssertTrue(result);
	
	// 5. At this point, old activation should be in "REMOVED" state
	
	PATSActivationStatus * serverOldActivationStatus = [_testServerApi getActivationStatus:activationData.activationId challenge:nil];
	XCTAssertNotNil(serverOldActivationStatus);
	XCTAssertTrue([serverOldActivationStatus.activationStatus isEqualToString:@"REMOVED"]);

	
	// 6. Create a new authentication and commit it to the SDK.
	
	auth = [self createAuthentication];
	result = [_sdk commitActivationWithAuthentication:auth error:&operationError];
	XCTAssertTrue(result);
	
	// 7. Cleanup - remove activation on the server.
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk removeActivationWithAuthentication:auth callback:^(NSError * _Nullable error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should be valid
		XCTAssertNotNil(task);
	}] boolValue];
	
	XCTAssertTrue(result);
}

/*
 In negative scenarios we're testing situations, when some configurations are invalid.
 For example, if selected application version is no longer supported, then the PA2 SDK
 should handle this situation properly.
 */

#pragma mark - Tests: Negative scenarios

- (void) testCreateActivationWhenApplicationIsUnsupported
{
	CHECK_TEST_CONFIG();
	
	//
	// This test validates situation, when previously issued application version
	// is no longer supported. The activation process must fail.
	//
	// Just for testing purposes, we need to create an another version, which is
	// supported and will be used for initiating the activation on the server's side.
	//
	
	[_sdk removeActivationLocal];
	
	BOOL result;
	__block NSError * reportedError;
	
	// 1) At first, we have to create an application version which is always supported.
	[_testServerApi createApplicationVersionIfDoesntExist:@"test-supported"];
	
	// 2) Unsupport application version, created in
	NSString * versionIdentifier = _testServerApi.appVersion.applicationVersionId;
	BOOL statusResult = [_testServerApi unsupportApplicationVersion:versionIdentifier];
	XCTAssertTrue(statusResult, @"Unable to change application status to 'unsupported'");
	if (!statusResult) {
		return;
	}
	
	// OK, application is not supported, try to create an activation
	
	// 3) SERVER: initialize an activation on server (this is typically implemented in the internet banking application)
	PATSInitActivationResponse * activationData = [_testServerApi initializeActivation:_testServerConfig.userIdentifier];
	NSString * activationCode = [activationData activationCodeWithSignature];
	
	__block NSString * activationFingerprint = nil;
	
	// 4) CLIENT: Start activation on client's side
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		NSString * activationName = _testServerConfig.userActivationName;
		id<PowerAuthOperationTask> task = [_sdk createActivationWithName:activationName activationCode:activationCode callback:^(PowerAuthActivationResult * result, NSError * error) {
			activationFingerprint = result.activationFingerprint;
			reportedError = error;
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
		
	}] boolValue];
	XCTAssertFalse(result, @"Activation on client side did fail.");
	
	// 5) Set application back to supported
	statusResult = [_testServerApi supportApplicationVersion:versionIdentifier];
	// If this fails, but everything is OK, then we just did not set app's supported flag back to TRUE.
	// This may indicate a change in SOAP API
	XCTAssertTrue(statusResult, @"Unable to change application status to 'supported'.");
}

- (void) testPasswordCorrectWhenBlocked
{
	CHECK_TEST_CONFIG();

	//
	// This test also validates data signing & vault unlock, when  activation is blocked.
	// This is due fact, that `validatePasswordCorrect` uses vault unlock internally
	// and that's quite complex operation.
	//
	
	BOOL result;
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	
	PATSInitActivationResponse * activationData = activation[0];
	PowerAuthAuthentication * auth = activation[1];
	
	// 1) Let's block activation
	PATSSimpleActivationStatus * serverStatus = [_testServerApi blockActivation:activationData.activationId];
	XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_BLOCKED);
	
	// 2) At first, use invalid password
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk validatePasswordCorrect:@"MustBeWrong" callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	XCTAssertFalse(result); // Must not pass. Activation is blocked
	
	// 3) Now use a valid password
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk validatePasswordCorrect:auth.usePassword callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	XCTAssertFalse(result);	// Must not pass. Activation is blocked
	
	// 4) Unblock
	serverStatus = [_testServerApi unblockActivation:activationData.activationId];
	XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_ACTIVE);
	
	// 5) Test password
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		id<PowerAuthOperationTask> task = [_sdk validatePasswordCorrect:auth.usePassword callback:^(NSError * error) {
			[waiting reportCompletion:@(error == nil)];
		}];
		XCTAssertNotNil(task);
	}] boolValue];
	XCTAssertTrue(result);	// Must pass, valid password, activation is active again
	
	// Cleanup
	[self removeLastActivation:activationData];
}

- (void) testWrongAPIUsage
{
	CHECK_TEST_CONFIG();
	
	//
	// This validates various API misuses.
	//
	
	NSArray * activation = [self createActivation:YES removeAfter:NO];
	XCTAssertTrue([activation.lastObject boolValue]);
	if (!activation) {
		return;
	}
	PATSInitActivationResponse * activationData = activation[0];
	//PowerAuthAuthentication * auth = activation[1];
	//BOOL result;
	{
		// Test for auth object without signature factors
		PowerAuthAuthentication * emptyAuth = [[PowerAuthAuthentication alloc] init];
		NSError * error = nil;
		PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:emptyAuth method:@"POST" uriId:@"some/uri/id" body:nil error:&error];
		XCTAssertNil(header);
		XCTAssertNotNil(error);
		XCTAssertEqualObjects(error.domain,PowerAuthErrorDomain);
		XCTAssertEqual(error.powerAuthErrorCode, PowerAuthErrorCode_WrongParameter);
	}
	
	// Cleanup
	[self removeLastActivation:activationData];
}

@end
