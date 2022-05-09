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

/**
 The `PowerAuthTokenTests` test class is similar to `PowerAuthSDKTests`
 but it's specialized for testing token-related code.
 
 */
@interface PowerAuthTokenTests : XCTestCase
@end

@implementation PowerAuthTokenTests
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


#pragma mark - Integration tests

- (void) runTestsForTokenStore:(id<PowerAuthTokenStore>)tokenStore
					activation:(PowerAuthSdkActivation*)activation
{
	PATSInitActivationResponse * activationData = activation.activationData;
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
	PowerAuthAuthorizationHttpHeader * header = [preciousToken generateHeader];
	BOOL result = [_helper validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
	XCTAssertTrue(result);
	
	header = [anotherToken generateHeader];
	result = [_helper validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
	XCTAssertTrue(result);

	// Remove token
	BOOL tokenRemoved = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		[tokenStore removeAccessTokenWithName:@"MyPreciousToken" completion:^(BOOL removed, NSError * _Nullable error) {
			[waiting reportCompletion:@(removed)];
		}];
	}] boolValue];
	XCTAssertTrue(tokenRemoved);
}

- (void) testTokens_WithRealTokenStore
{
	CHECK_TEST_CONFIG();
	
	//
	// The purpose of this test is to validate whether token store produced in PowerAuthSDK
	// works correctly. We're using the same battery of tests than
	
	PowerAuthSdkActivation * activation = [_helper createActivation:YES];
	if (!activation) {
		return;
	}
	[self runTestsForTokenStore:_sdk.tokenStore activation:activation];
	
	// Cleanup
	[_helper cleanup];
	
	XCTAssertFalse(_sdk.tokenStore.canRequestForAccessToken);
}

@end
