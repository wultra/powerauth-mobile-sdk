/*
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
    PowerAuthSdkTestHelper * _helper;
    PowerAuthSDK * _sdk;
    
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
#define HAS_ASYNC_TASK_PROTOCOL     1
#define HAS_PENDING_COMMIT_STATE    1

#define UPGRADE_OLD_PROTOCOL    @"2.1"
#define UPGRADE_NEW_PROTOCOL    @"3.1"

// Adjust SDK specific objects
#if HAS_ASYNC_TASK_PROTOCOL == 1
#define PA2TestsOperationTask   id<PowerAuthOperationTask>
#else
#define PA2TestsOperationTask   PA2OperationTask*
#endif

#if HAS_PENDING_COMMIT_STATE == 1
#define PA2TestActivationState_PendingCommit    PowerAuthActivationState_PendingCommit
#else
#define PA2TestActivationState_PendingCommit    PowerAuthActivationState_OTP_Used
#endif

#pragma mark - Test setup

- (void)setUp
{
    [super setUp];
    _helper = [PowerAuthSdkTestHelper createDefault];
    _sdk = _helper.sdk;
    
    // Load protocol upgrade specific parameters
    PowerAuthTestServerConfig * testServerConfig = _helper.testServerConfig;
    _upgradeStep = [[testServerConfig configValueForKey:@"upgradeStep" defaultValue:@0] integerValue];
    _upgradeOldProtocolVersion = [testServerConfig configValueForKey:@"upgradeOldProtocolVersion" defaultValue:UPGRADE_OLD_PROTOCOL];
    _upgradeNewProtocolVersion = [testServerConfig configValueForKey:@"upgradeNewProtocolVersion" defaultValue:UPGRADE_NEW_PROTOCOL];
    _upgradeProtocolVersion = _upgradeStep == 2 ? _upgradeNewProtocolVersion : _upgradeOldProtocolVersion;
    
    // Print report
    NSLog(@"=======================================================================");
    NSLog(@"The protocol upgrade tests will run against following servers:");
    NSLog(@"    REST API Server: %@", testServerConfig.restApiUrl);
    NSLog(@"    SOAP API Server: %@", testServerConfig.soapApiUrl);
    NSLog(@"               User: %@", testServerConfig.userIdentifier);
    if (_upgradeStep > 0) {
        NSLog(@"            Upgrade: %@ step, with protocol %@", _upgradeStep == 2 ? @"Validate" : @"Create", _upgradeProtocolVersion);
    } else {
        NSLog(@"            Upgrade: Disabled");
    }
    NSLog(@"=======================================================================");
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

/**
 Validates password on server. Returns YES if password is valid.
 */
- (NSError*) checkForPassword:(NSString*)password
{
    NSError * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        PA2TestsOperationTask task = [_sdk validatePasswordCorrect:password callback:^(NSError * error) {
            [waiting reportCompletion:error];
        }];
        XCTAssertNotNil(task);
    }];
    return result;
}

#pragma mark - Integration tests

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
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES removeAfter:NO];
    if (!activation) {
        return;
    }
    
    PATSInitActivationResponse * activationData = activation.activationData;
    PowerAuthAuthentication * auth = activation.credentials;
    
    NSString * activationStateData = [[_helper sessionCoreSerializedState] base64EncodedStringWithOptions:0];
    NSUserDefaults * defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:auth.usePassword forKey:s_PossessionFactorKey];
    [defaults setObject:activationData.activationId forKey:s_ActivationIdKey];
    [defaults setObject:activationStateData forKey:s_StateDataKey];
    [defaults synchronize];
    
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    
    NSLog(@"=======================================================================");
    NSLog(@"Upgrade params (for old SDK step):");
    NSLog(@"  - password    %@", auth.usePassword);
    NSLog(@"  - act-id      %@", activationData.activationId);
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
    BOOL stateDeserialization = [_helper sessionCoreDeserializeState:stateData];
    if (!stateDeserialization) {
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
    
    NSError * result = [self checkForPassword:password];
    XCTAssertNotNil(result);
    XCTAssertTrue([result.domain isEqualToString:PowerAuthErrorDomain]);
    XCTAssertTrue(result.code == PowerAuthErrorCode_PendingProtocolUpgrade);
    XCTAssertTrue(result.powerAuthErrorCode == PowerAuthErrorCode_PendingProtocolUpgrade);
    
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    
    result = [self checkForPassword:password];
    XCTAssertNil(result);
    
    status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithPassword:password];
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
