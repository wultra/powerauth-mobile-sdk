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
#import "PowerAuthSdkTestHelper.h"

@interface PowerAuthInvalidCurveTests: XCTestCase
@end

@implementation PowerAuthInvalidCurveTests
{
	PowerAuthSdkTestHelper * _helper;
	PowerAuthSDK * _sdk;
}

#pragma mark - Test setup

- (void)setUp
{
	[super setUp];
	_helper = [PowerAuthSdkTestHelper createDefault];
	[_helper printConfig];
	_sdk = _helper.sdk;
}

- (void) tearDown
{
	[_helper cleanup];
	[super tearDown];
}

#pragma mark - Helper utilities

/**
 Checks whether the test config is valid. You should use this macro in all unit tests
 defined in this class.
 */
#define CHECK_TEST_CONFIG()		\
	if (!_sdk) {				\
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
