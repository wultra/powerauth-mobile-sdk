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
#define CHECK_TEST_CONFIG()     \
    if (!_sdk) {                \
        XCTFail(@"Test configuration is not valid.");   \
        return;                 \
    }

/**
 Checks boolean value in result local variable and returns |obj| value if contains NO.
 */
#define CHECK_RESULT_RET(obj)   \
    if (result == NO) {         \
        return obj;             \
    }


#pragma mark - Integration tests

- (void) testBasicTokenOperations
{
    CHECK_TEST_CONFIG();
    
    // The purpose of this test is to validate whether token store produced in PowerAuthSDK
    // works correctly. We're using the same battery of tests than
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PATSInitActivationResponse * activationData = activation.activationData;
    id<PowerAuthTokenStore> tokenStore = _sdk.tokenStore;
    
    XCTAssertTrue(tokenStore.canRequestForAccessToken);
    
    // Create first token...
    PowerAuthAuthentication * possession = [PowerAuthAuthentication possession];
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
    
    
    // Cleanup
    [_helper cleanup];
    
    XCTAssertFalse(_sdk.tokenStore.canRequestForAccessToken);
}

- (void) testGroupedCreateTokenRequests
{
    CHECK_TEST_CONFIG();
    
    // This test validates whether the multiple create token requests
    // created at the same time leads to the same token.
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    __block PowerAuthToken * token1 = nil;
    __block PowerAuthToken * token2 = nil;
    __block PowerAuthToken * token3 = nil;
    __block PowerAuthToken * token4 = nil;
    __block PowerAuthToken * token5 = nil;
    __block NSUInteger completionCount = 0;
    const NSUInteger minCompletionCount = 6;
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        PowerAuthAuthentication * auth = _helper.authPossessionWithKnowledge;
        [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token1 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token2 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"AnotherToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token4 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        id<PowerAuthOperationTask> task = [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTFail(@"This should be never called");
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [task cancel];
        [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token3 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"AnotherToken" authentication:auth completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token5 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"AnotherToken" authentication:_helper.authPossession completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNil(token);
            XCTAssertTrue(error.powerAuthErrorCode == PowerAuthErrorCode_WrongParameter);
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
    }];
    
    XCTAssertTrue([token1 isEqualToToken:token2]);
    XCTAssertTrue([token1 isEqualToToken:token3]);
    XCTAssertTrue([token2 isEqualToToken:token3]);
    XCTAssertTrue([token4 isEqualToToken:token5]);
    XCTAssertFalse([token4 isEqualToToken:token1]);
}

- (void) testCreateTokenWithDifferentAuth
{
    CHECK_TEST_CONFIG();
    
    // This test validates whether SDK validates signature factors for already
    // created token.
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    __block PowerAuthToken * token1 = nil;
    __block PowerAuthToken * token2 = nil;
    __block NSUInteger completionCount = 0;
    const NSUInteger minCompletionCount = 2;
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:_helper.authPossession completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token1 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"AnotherToken" authentication:_helper.authPossessionWithKnowledge completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNotNil(token);
            token2 = token;
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
    }];
    completionCount = 0;
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk.tokenStore requestAccessTokenWithName:@"SameToken" authentication:_helper.authPossessionWithKnowledge completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNil(token);
            XCTAssertTrue(error.powerAuthErrorCode == PowerAuthErrorCode_WrongParameter);
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
        [_sdk.tokenStore requestAccessTokenWithName:@"AnotherToken" authentication:_helper.authPossession completion:^(PowerAuthToken * token, NSError * error) {
            XCTAssertNil(token);
            XCTAssertTrue(error.powerAuthErrorCode == PowerAuthErrorCode_WrongParameter);
            if (++completionCount >= minCompletionCount) {
                [waiting reportCompletion:nil];
            }
        }];
    }];
}

@end
