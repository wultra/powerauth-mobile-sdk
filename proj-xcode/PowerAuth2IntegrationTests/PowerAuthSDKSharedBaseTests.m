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

#import "PowerAuthSDKSharedBaseTests.h"
#import "ProcessSuspensionHelper.h"

@implementation PowerAuthSDKSharedBaseTests
{
    PowerAuthSdkTestHelper * _altHelper;
    PowerAuthSDK * _altSdk;
    NSString * _app1;
    NSString * _app2;
    NSString * _appGroupId;
    NSString * _instanceId;
    NSString * _keychainAccessGroup;
    
    NSOperationQueue * _app1Queue;
    NSOperationQueue * _app2Queue;
    
    AsyncHelper * _waitForQueuesTask;
}

- (void) setUp
{
    _app1 = @"appInstance_1";
    _app2 = @"appInstance_2";
    // Tests runs only in Simulator and Simulator doesn't support keychain access groups,
    // so it can be fake.
    _keychainAccessGroup = @"fake.accessGroup";
#if TARGET_OS_MACCATALYST == 1
    _appGroupId = @"group.com.wultra.testGroup";
    _instanceId = @"SharedInstanceTests-Catalyst";
#else
    _appGroupId = @"group.com.wultra.testGroup";
    _instanceId = @"SharedInstanceTests";
#endif
    [super setUp];
}

- (void) tearDown
{
    [self waitForTestQueues];
    _app1Queue.suspended = YES;
    _app2Queue.suspended = YES;

    [_altHelper cleanup];
    [super tearDown];
    
    // Make sure no external pending operation is left behind. If yes,
    // then this will likely affect unrelated tests executed after.
    XCTAssertNil(_sdk.externalPendingOperation);
    XCTAssertNil(_altSdk.externalPendingOperation);
}

- (void) prepareConfigs:(PowerAuthConfiguration **)configuration
        biometricConfig:(PowerAuthBiometricConfiguration **)biometricConfiguration
         keychainConfig:(PowerAuthKeychainConfiguration **)keychainConfiguration
           clientConfig:(PowerAuthClientConfiguration **)clientConfiguration
            forTestName:(NSString*)testName
{
#if defined(PA2_SIMPLIFIED_CONFIG)
    *configuration = [[PowerAuthConfiguration alloc] initWithInstanceId:_instanceId baseEndpointUrl:(*configuration).baseEndpointUrl configuration:(*configuration).configuration];
#else
    (*configuration).instanceId = _instanceId;
#endif
    
    PowerAuthSharingConfiguration * sharingConfig = [[PowerAuthSharingConfiguration alloc] initWithAppGroup:_appGroupId appIdentifier:_app1 keychainAccessGroup:_keychainAccessGroup];
    (*configuration).sharingConfiguration = sharingConfig;
    
    [super prepareConfigs:configuration
          biometricConfig:biometricConfiguration
           keychainConfig:keychainConfiguration
             clientConfig:clientConfiguration
              forTestName:testName];
}

- (BOOL) prepareAltSdk
{
    return [self prepareAltSdk:YES targetAlgorithm:self.powerAuthAlgorithm];
}

- (BOOL) prepareAltSdk:(BOOL)removeActivation
       targetAlgorithm:(PowerAuthAlgorithm)algorithm
{
    if (!self.sdk) {
        return NO;
    }
    
    PowerAuthConfiguration * altConfig = [self.helper.sdk.configuration copy];
    altConfig.algorithm = algorithm;
    altConfig.sharingConfiguration = [[PowerAuthSharingConfiguration alloc] initWithAppGroup:_appGroupId
                                                                               appIdentifier:_app2
                                                                         keychainAccessGroup:_keychainAccessGroup];
    _altHelper = [PowerAuthSdkTestHelper clone:self.helper
                             withConfiguration:altConfig
                              removeActivation:removeActivation];
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
        __block int completion = 2;
        [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            _waitForQueuesTask = waiting;
            void (^block)(void) = ^{
                BOOL done;
                @synchronized (waiting) {
                    done = --completion == 0;
                }
                if (done) {
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

/**
 Starts `count` operations on the shared SDK and waits until all of them are completed. Every `statusEvery`-th
 operation fetches the activation status, the others validate the password twice. The second password validation
 started at `cancelAt` index is cancelled immediately.
 */
- (void) runConcurrentOperations:(int)count statusEvery:(int)statusEvery cancelAt:(int)cancelAt credentials:(PowerAuthAuthentication*)credentials
{
    @try {
        [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            // Callbacks are called on the main thread, while operations are started on this thread, so the counter
            // must be synchronized. It starts at 1, so it cannot reach zero before all operations are started.
            __block NSUInteger completionCount = 1;
            void (^expect)(NSUInteger) = ^(NSUInteger n) {
                @synchronized (waiting) {
                    completionCount += n;
                }
            };
            void (^complete)(void) = ^{
                [waiting extendWaitingTime];
                [_waitForQueuesTask extendWaitingTime];
                BOOL done;
                @synchronized (waiting) {
                    done = --completionCount == 0;
                }
                if (done) {
                    [waiting reportCompletion:nil];
                }
            };
            for (int i = 0; i < count; i++) {
                if (i % statusEvery == 0) {
                    expect(1);
                    [self.sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
                        XCTAssertNotNil(status);
                        complete();
                    }];
                } else {
                    const BOOL cancel = i == cancelAt;
                    expect(cancel ? 1 : 2);
                    [self.sdk testCorePassword:credentials.password callback:^(NSError * error) {
                        XCTAssertNil(error);
                        complete();
                    }];
                    id<PowerAuthOperationTask> task = [self.sdk testCorePassword:credentials.password callback:^(NSError * error) {
                        if (!cancel) {
                            XCTAssertNil(error);
                            complete();
                        }
                    }];
                    if (cancel) {
                        [task cancel];
                    }
                }
            }
            complete();
        }];
    } @catch (NSException *exception) {
        XCTFail(@"Test failed with exception %@", exception);
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
        [self runConcurrentOperations:50 statusEvery:5 cancelAt:29 credentials:credentials];
    }];
    [_app2Queue addOperationWithBlock:^{
        [self runConcurrentOperations:50 statusEvery:7 cancelAt:-1 credentials:credentials];
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

    // Try to synchronize the time do do not mess with the precision of calling the concurrent
    // activations.
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [self.sdk.timeSynchronizationService synchronizeTimeWithCallback:^(NSError * _Nullable error) {
            [waiting reportCompletion:nil];
        } callbackQueue:dispatch_get_main_queue()];
    }];
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_altSdk.timeSynchronizationService synchronizeTimeWithCallback:^(NSError * _Nullable error) {
            [waiting reportCompletion:nil];
        } callbackQueue:dispatch_get_main_queue()];
    }];
    
    PowerAuthAuthentication * credentials = [self.helper createPersistAuthenticationWithFlags:0];
    PowerAuthActivationResult * activationResult = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:[activationData activationCodeWithSignature] name:nil error:nil];
        id task = [self.sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
            [waiting reportCompletion:result];
        }];
        XCTAssertNotNil(task);
        
        PowerAuthExternalPendingOperation * extOp1 = self.sdk.externalPendingOperation;
        XCTAssertNil(extOp1);       // Instance that initiated activation, must return nil.
        
        PowerAuthExternalPendingOperation * extOp2 = _altSdk.externalPendingOperation;
        XCTAssertNotNil(extOp2);    // Other instance must have data
        XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, extOp2.externalOperationType);
        XCTAssertTrue([_app1 isEqualToString:extOp2.externalApplicationId]);
        
        id<PowerAuthOperationTask> task2 = [_altSdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
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
    XCTAssertNotNil(extOp2);    // Other instance must have data
    XCTAssertEqual(PowerAuthExternalPendingOperationType_Activation, extOp2.externalOperationType);
    XCTAssertTrue([_app1 isEqualToString:extOp2.externalApplicationId]);
    
    
    NSError * error = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [self.sdk persistActivationWithCorePassword:credentials.password callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:error];
        }];
    }];
    XCTAssertNil(error);
    
    XCTAssertTrue([self.sdk hasValidActivation]);
    XCTAssertTrue([_altSdk hasValidActivation]);
    XCTAssertNil([self.sdk externalPendingOperation]);
    XCTAssertNil([_altSdk externalPendingOperation]);
    XCTAssertNil(self.sdk.externalPendingOperation);
    XCTAssertNil(_altSdk.externalPendingOperation);
    
    // Commit activation on the server.
    if (!self.helper.testServerConfig.isServerAutoCommit) {
        [self.helper.testServerApi commitActivation:activationData.activationId];
    }
    
    PowerAuthActivationStatus * status1 = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [self.sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            [waiting reportCompletion:status];
        }];
    }];
    XCTAssertNotNil(status1);
    XCTAssertEqual(PowerAuthActivationState_Active, status1.state);
    
    PowerAuthActivationStatus * status2 = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_altSdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            [waiting reportCompletion:status];
        }];
    }];
    XCTAssertNotNil(status2);
    XCTAssertEqual(PowerAuthActivationState_Active, status2.state);
}

/// Returns `PowerAuthActivationResult`, or `NSError` in case of failure.
- (id) createActivation:(PATSInitActivationResponse*)activationData sdk:(PowerAuthSDK*)sdk
{
    return [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:[activationData activationCodeWithSignature] name:nil error:nil];
        [sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
            [waiting reportCompletion:result ?: error];
        }];
    }];
}

- (NSError*) persistActivation:(PowerAuthSDK*)sdk credentials:(PowerAuthAuthentication*)credentials
{
    return [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [sdk persistActivationWithCorePassword:credentials.password callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:error];
        }];
    }];
}

- (void) testPendingActivation_ProcessSuspension
{
    if (![self prepareAltSdk]) {
        XCTFail(@"Failed to initialize SDK objects");
        return;
    }
    [ProcessSuspensionHelper startSimulation];
    [self addTeardownBlock:^{
        [ProcessSuspensionHelper stopSimulation];
    }];
    
    PATSInitActivationResponse * activationData = [self.helper prepareActivation:YES activationOtp:nil];
    XCTAssertNotNil(activationData);
    if (!activationData) return;
    
    PowerAuthAuthentication * credentials = [self.helper createPersistAuthenticationWithFlags:0];
    PowerAuthActivationResult * activationResult = [self createActivation:activationData sdk:self.sdk];
    XCTAssertTrue([activationResult isKindOfClass:[PowerAuthActivationResult class]]);
    // Keep activation data in the helper to remove activation automatically at the end of the test.
    [self.helper assignCustomActivationData:activationData activationResult:activationResult credentials:credentials];
    
    NSError * error = [self createActivation:activationData sdk:_altSdk];
    XCTAssertEqual(PowerAuthErrorCode_ExternalPendingOperation, error.powerAuthErrorCode);
    
    // The pending activation must survive the suspension and the application
    // must own the operation again once it's resumed.
    [ProcessSuspensionHelper suspendProcess];
    XCTAssertTrue([self.sdk hasPendingActivation]);
    XCTAssertNil(self.sdk.externalPendingOperation);
    XCTAssertTrue([_app1 isEqualToString:_altSdk.externalPendingOperation.externalApplicationId]);
    error = [self createActivation:activationData sdk:_altSdk];
    XCTAssertEqual(PowerAuthErrorCode_ExternalPendingOperation, error.powerAuthErrorCode);
    
    XCTAssertNil([self persistActivation:self.sdk credentials:credentials]);
    XCTAssertTrue([self.sdk hasValidActivation]);
    XCTAssertTrue([_altSdk hasValidActivation]);
    XCTAssertNil(self.sdk.externalPendingOperation);
    XCTAssertNil(_altSdk.externalPendingOperation);
}

- (void) testPendingActivation_StartedInAnotherAppDuringSuspension
{
    if (![self prepareAltSdk]) {
        XCTFail(@"Failed to initialize SDK objects");
        return;
    }
    [ProcessSuspensionHelper startSimulation];
    [self addTeardownBlock:^{
        [ProcessSuspensionHelper stopSimulation];
    }];
    
    PATSInitActivationResponse * activationData1 = [self.helper prepareActivation:YES activationOtp:nil];
    PATSInitActivationResponse * activationData2 = [self.helper prepareActivation:YES activationOtp:nil];
    XCTAssertNotNil(activationData1);
    XCTAssertNotNil(activationData2);
    if (!activationData1 || !activationData2) return;
    
    PowerAuthAuthentication * credentials = [self.helper createPersistAuthenticationWithFlags:0];
    PowerAuthActivationResult * activationResult1 = [self createActivation:activationData1 sdk:self.sdk];
    XCTAssertTrue([activationResult1 isKindOfClass:[PowerAuthActivationResult class]]);
    
    // The suspended application doesn't block other applications.
    [ProcessSuspensionHelper suspendProcess];
    PowerAuthActivationResult * activationResult2 = [self createActivation:activationData2 sdk:_altSdk];
    XCTAssertTrue([activationResult2 isKindOfClass:[PowerAuthActivationResult class]]);
    
    // The first application is resumed. It no longer owns the operation, but its activation is still pending.
    XCTAssertTrue([_app2 isEqualToString:self.sdk.externalPendingOperation.externalApplicationId]);
    XCTAssertNil(_altSdk.externalPendingOperation);
    XCTAssertTrue([self.sdk hasPendingActivation]);
    XCTAssertTrue([_altSdk hasPendingActivation]);
    
    // The first persisted activation wins.
    XCTAssertNil([self persistActivation:_altSdk credentials:credentials]);
    XCTAssertTrue([_altSdk hasValidActivation]);
    XCTAssertTrue([self.sdk hasValidActivation]);
    XCTAssertFalse([self.sdk hasPendingActivation]);
    XCTAssertTrue([activationData2.activationId isEqualToString:self.sdk.activationIdentifier]);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationState, [self persistActivation:self.sdk credentials:credentials].powerAuthErrorCode);
    XCTAssertNil(self.sdk.externalPendingOperation);
    XCTAssertNil(_altSdk.externalPendingOperation);
    
    // The activation abandoned by the first application is not removed by the helpers.
    [self.helper.testServerApi removeActivation:activationData1.activationId];
}

- (void) testConcurrentTokens
{
    if (![self prepareAltSdk]) {
        XCTFail(@"Failed to initialize SDK objects");
        return;
    }
    [self.helper createActivation:YES];
    PowerAuthAuthentication * credentials = self.helper.authPossessionWithKnowledge;
    XCTAssertTrue([self.sdk hasValidActivation]);
    XCTAssertTrue([_altSdk hasValidActivation]);
    
    NSString * token1 = @"SharedToken1";
    NSString * token2 = @"SharedToken2";
    
    XCTAssertFalse([self.sdk.tokenStore hasLocalTokenWithName:token1]);
    XCTAssertFalse([self.sdk.tokenStore hasLocalTokenWithName:token2]);
    XCTAssertFalse([_altSdk.tokenStore hasLocalTokenWithName:token1]);
    XCTAssertFalse([_altSdk.tokenStore hasLocalTokenWithName:token2]);
    
    PowerAuthToken * token1A = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [self.sdk.tokenStore requestAccessTokenWithName:token1 authentication:credentials completion:^(PowerAuthToken * token, NSError * error) {
            [waiting reportCompletion:token];
        }];
    }];
    XCTAssertNotNil(token1A);
    XCTAssertTrue([self.sdk.tokenStore hasLocalTokenWithName:token1]);
    XCTAssertTrue([_altSdk.tokenStore hasLocalTokenWithName:token1]);
    PowerAuthToken * token2B =[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_altSdk.tokenStore requestAccessTokenWithName:token2 authentication:credentials completion:^(PowerAuthToken * token, NSError * error) {
            [waiting reportCompletion:token];
        }];
    }];
    XCTAssertNotNil(token2B);
    
    PowerAuthToken * token1B = [_altSdk.tokenStore localTokenWithName:token1];
    PowerAuthToken * token2A = [self.sdk.tokenStore localTokenWithName:token2];
    XCTAssertFalse([token1A isEqualToToken:token1B]);
    XCTAssertFalse([token2A isEqualToToken:token2B]);
    XCTAssertTrue([token1A.tokenIdentifier isEqualToString:token1B.tokenIdentifier]);
    XCTAssertTrue([token2A.tokenIdentifier isEqualToString:token2B.tokenIdentifier]);
    
    [AsyncHelper waitForNextSecond];
    
    PowerAuthHttpHeader * header1A = [token1A generateHeader];
    PowerAuthHttpHeader * header1B = [token1B generateHeader];
    PowerAuthHttpHeader * header2A = [token2A generateHeader];
    PowerAuthHttpHeader * header2B = [token2B generateHeader];
    NSLog(@"Header1A = %@", header1A.value);
    NSLog(@"Header1B = %@", header1B.value);
    NSLog(@"Header2A = %@", header2A.value);
    NSLog(@"Header2B = %@", header2B.value);

    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_altSdk.tokenStore removeAccessTokenWithName:token1 completion:^(BOOL removed, NSError * _Nullable error) {
            XCTAssertTrue(removed);
            [waiting reportCompletion:nil];
        }];
    }];
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [self.sdk.tokenStore removeAccessTokenWithName:token2 completion:^(BOOL removed, NSError * _Nullable error) {
            XCTAssertTrue(removed);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertFalse([self.sdk.tokenStore hasLocalTokenWithName:token1]);
    XCTAssertFalse([self.sdk.tokenStore hasLocalTokenWithName:token2]);
    XCTAssertFalse([_altSdk.tokenStore hasLocalTokenWithName:token1]);
    XCTAssertFalse([_altSdk.tokenStore hasLocalTokenWithName:token2]);
}

- (void) testProtocolUpgrade_Concurrent
{
    if (self.powerAuthAlgorithm == PowerAuthAlgorithm_LEGACY_P256) {
        NSLog(@"Test not available for LEGACY_P256");
        return;
    }
    
    _sdk = [_helper prepareActivationForUpgradeTest:self.powerAuthAlgorithm withFlags:0];
    
    if (![self prepareAltSdk:NO targetAlgorithm:self.powerAuthAlgorithm]) {
        XCTFail(@"Failed to initialize SDK objects");
        return;
    }
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _altSdk.currentAlgorithm);
    
    PowerAuthProtocolUpgradeResult * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk startProtocolUpgradeWithCorePassword:self.helper.authPossessionWithKnowledge.password callback:^(PowerAuthProtocolUpgradeResult * _Nullable result, NSError * _Nullable error) {
            [waiting reportCompletion:result];
        }];
        
        // Instance initiated upgrade has external pending operation set to nil
        XCTAssertNil(_sdk.externalPendingOperation);
        // Other instance has external pending operation available
        XCTAssertNotNil(_altSdk.externalPendingOperation);
        XCTAssertEqual(PowerAuthExternalPendingOperationType_ProtocolUpgrade, _altSdk.externalPendingOperation.externalOperationType);
        
    }];
    XCTAssertNotNil(result);
    
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
    XCTAssertEqual(self.powerAuthAlgorithm, _altSdk.currentAlgorithm);
}

- (void) testProtocolUpgrade_ConcurrentLegacyVsV4
{
    if (self.powerAuthAlgorithm == PowerAuthAlgorithm_LEGACY_P256) {
        NSLog(@"Test not available for LEGACY_P256");
        return;
    }

    _sdk = [_helper prepareActivationForUpgradeTest:self.powerAuthAlgorithm withFlags:0];
    
    if (![self prepareAltSdk:NO targetAlgorithm:PowerAuthAlgorithm_LEGACY_P256]) {
        XCTFail(@"Failed to initialize SDK objects");
        return;
    }
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _altSdk.currentAlgorithm);

    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:YES];
    XCTAssertNotNil(result);
    
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
    XCTAssertEqual(self.powerAuthAlgorithm, _altSdk.currentAlgorithm);
    
    PowerAuthPassword * password = [_helper.authPossessionWithKnowledge.password copyToImmutable];
    XCTAssertTrue([_helper checkForCorePassword:password]);
    XCTAssertTrue([_altHelper checkForCorePassword:password]);
}

@end
