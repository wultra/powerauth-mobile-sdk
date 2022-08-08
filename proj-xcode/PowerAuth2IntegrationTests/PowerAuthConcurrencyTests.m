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
@interface PowerAuthConcurrencyTests : XCTestCase
@end

@implementation PowerAuthConcurrencyTests
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

#pragma mark - Tests

- (void) testTokens_ConcurrentCreationAndRemove
{
    CHECK_TEST_CONFIG();
    
    //
    // The purpose of this test is to validate whether token store produced in PowerAuthSDK
    // works correctly. We're using the same battery of tests than
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    id<PowerAuthTokenStore> tokenStore = _sdk.tokenStore;
    NSMutableArray<PowerAuthToken*> * tokens = [NSMutableArray array];
    const NSInteger number_of_tokens = 20;
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        PowerAuthAuthentication * possession = [PowerAuthAuthentication possession];
        __block NSInteger attempts = 0;
        for (NSInteger i = 0; i < number_of_tokens; i++) {
            NSString * token_name = [NSString stringWithFormat:@"test_token_%@", @(i)];
            [tokenStore requestAccessTokenWithName:token_name authentication:possession completion:^(PowerAuthToken * _Nullable token, NSError * _Nullable error) {
                attempts++;
                if (!error && token) {
                    [tokens addObject:token];
                }
                if (attempts == number_of_tokens) {
                    [waiting reportCompletion:nil];
                }
            }];
        }
    }];
    
    XCTAssertTrue(tokens.count == number_of_tokens, @"Tokens attempted: %@   created %@", @(number_of_tokens), @(tokens.count));
    
    if (tokens.count > 0) {
        // Now remove all crated tokens
        __block NSInteger removed_tokens = 0;
        [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            __block NSInteger removeOperations = 0;
            [tokens enumerateObjectsUsingBlock:^(PowerAuthToken * _Nonnull token, NSUInteger idx, BOOL * _Nonnull stop) {
                [tokenStore removeAccessTokenWithName:token.tokenName completion:^(BOOL removed, NSError * _Nullable error) {
                    removeOperations++;
                    if (removed && !error) {
                        removed_tokens++;
                    }
                    if (removeOperations == tokens.count) {
                        [waiting reportCompletion: nil];
                    }
                }];
            }];
        }];
        
        XCTAssertTrue(removed_tokens == tokens.count);
    } else {
        XCTFail(@"All operations failed!!");
    }
    
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active, @"Activation should be still valid");
    
    // Cleanup
    [_helper cleanup];
    
    XCTAssertFalse(_sdk.tokenStore.canRequestForAccessToken);
}

@end
