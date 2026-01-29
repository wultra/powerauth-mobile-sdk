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

#import "PowerAuthSDKBaseTests.h"
#import "PA2ObjectSerialization.h"

@implementation PowerAuthSDKBaseTests

#pragma mark - Integration tests

- (void) testAlgorithmSetup
{
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
}

#pragma mark - Activation

/*
 In positive scenarios we're testing situations, when everything looks fine.
 */
#pragma mark - Tests: Positive scenarios

- (void) testCreateActivationWithSignature
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES removeAfter:YES];
    XCTAssertTrue(activation.success);
}


- (void) testCreateActivationWithoutSignature
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:NO removeAfter:YES];
    XCTAssertTrue(activation.success);
}

- (void) testCreateActivationWithOtpAndSignature
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES
                                                      activationOtp:@"12345"
                                                        removeAfter:YES];
    XCTAssertTrue(activation.success);
}

- (void) testCreateActivationAndPersistWithPassword
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_RemoveAfter
                                                               activationOtp:nil];
    XCTAssertTrue(activation.success);
}

- (void) testCreateActivationAndPersistWithCorePassword
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithCorePassword | TestActivationFlags_RemoveAfter
                                                               activationOtp:nil];
    XCTAssertTrue(activation.success);
}


- (void) testRemoveActivation
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;

    // Remove activation from the server
    NSError * removeError = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk removeActivationWithAuthentication:auth callback:^(NSError * error) {
            [waiting reportCompletion:error];
        }];
        XCTAssertNotNil(task);
    }];
    XCTAssertNil(removeError);
    XCTAssertNil(_sdk.activationIdentifier);
}

- (void) testPasswordCorrect
{
    CHECK_TEST_CONFIG();
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
    // 1) At first, use invalid password
    result = [_helper checkForPassword:@"MustBeWrong"];
    XCTAssertFalse(result); // if YES then something is VERY wrong. The wrong password passed the test.
    
    // 2) Now use a valid password
    result = [_helper checkForCorePassword:auth.password];
    XCTAssertTrue(result);  // if NO then a valid password did not pass the test.
}


- (void) testChangePassword
{
    CHECK_TEST_CONFIG();
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
    PowerAuthCorePassword * newPassword = [PowerAuthCorePassword passwordWithString:@"nbusr321"];
    
    // 1) Change password in two steps
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task1 = [_sdk beginPasswordChangeWithCorePassword:auth.password callback:^(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error) {
            XCTAssertNil(error);
            if (!error) {
                // Now change password
                id<PowerAuthOperationTask> task2 = [_sdk finishPasswordChangeWithNewCorePassword:newPassword changeData:changeData callback:^(NSError * _Nullable error) {
                    [waiting reportCompletion:@(error == nil)];
                }];
                // Returned task should be present for non-legacy algorithms
                if (self.powerAuthAlgorithm != PowerAuthAlgorithm_LEGACY_P256) {
                    // In Legacy mode, password is changed locally
                    XCTAssertNotNil(task2);
                }
            } else {
                // failure in step 1
                [waiting reportCompletion:@NO];
            }
        }];
        XCTAssertNotNil(task1);
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now validate that new password
    result = [_helper checkForCorePassword:newPassword];
    XCTAssertTrue(result);
    
    // Now use string version instead of core password
    
    NSString * oldStringPassword = newPassword.extractedPassword;
    NSString * newStringPassword = auth.password.extractedPassword;
    
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task1 = [_sdk beginPasswordChangeWithPassword:oldStringPassword callback:^(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error) {
            XCTAssertNil(error);
            if (!error) {
                // Now change password
                id<PowerAuthOperationTask> task2 = [_sdk finishPasswordChangeWithNewPassword:newStringPassword changeData:changeData callback:^(NSError * _Nullable error) {
                    [waiting reportCompletion:@(error == nil)];
                }];
                // Returned task should be present for non-legacy algorithms
                if (self.powerAuthAlgorithm != PowerAuthAlgorithm_LEGACY_P256) {
                    // In Legacy mode, password is changed locally
                    XCTAssertNotNil(task2);
                }
            } else {
                // failure in step 1
                [waiting reportCompletion:@NO];
            }
        }];
        XCTAssertNotNil(task1);
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now validate that new password
    result = [_helper checkForPassword:newStringPassword];
    XCTAssertTrue(result);
}

// PA2_DEPRECATED(2.0.0)
- (void) testChangePasswordDeprecated
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

    CHECK_TEST_CONFIG();
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
    PowerAuthCorePassword * newPassword = [PowerAuthCorePassword passwordWithString:@"nbusr321"];
    
    // 1) At first, validate password with using deprecated function
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk validateCorePassword:auth.password callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now change password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk changeCorePasswordFrom:auth.password to:newPassword callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        if (self.powerAuthAlgorithm != PowerAuthAlgorithm_LEGACY_P256) {
            // In Legacy mode, password is changed locally
            XCTAssertNotNil(task);
        }
    }] boolValue];
    XCTAssertTrue(result);
    
    // 3) And finally check the new password
    result = [_helper checkForCorePassword:newPassword];
    XCTAssertTrue(result);
    
    // Now use string version instead of core password
    
    NSString * oldStringPassword = newPassword.extractedPassword;
    NSString * newStringPassword = auth.password.extractedPassword;
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk validatePassword:oldStringPassword callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertTrue(result);
    
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk changePasswordFrom:oldStringPassword to:newStringPassword callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        if (self.powerAuthAlgorithm != PowerAuthAlgorithm_LEGACY_P256) {
            // In Legacy mode, password is changed locally
            XCTAssertNotNil(task);
        }
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now validate that new password
    result = [_helper checkForPassword:newStringPassword];
    XCTAssertTrue(result);
    
#pragma clang diagnostic pop
}


- (void) testAuthentication
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates functions for PA signature calculations.
    //
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithFakeBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PowerAuthAuthentication * auth_possession = _helper.authPossession;
    PowerAuthAuthentication * auth_possession_knowledge = _helper.authPossessionWithKnowledge;
    PowerAuthAuthentication * auth_possession_biometry = _helper.authPossessionWithBiometry;
    
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
            result = [_helper validateAuthentication:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0];
            XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        }
        NSString * get_method = online_mode ? @"GET" : @"POST";
        result = [_helper validateAuthentication:auth_possession_knowledge data:data method:get_method uriId:@"/hello/hacker" online:online_mode cripple:0];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateAuthentication:auth_possession_biometry data:data method:get_method uriId:@"/hello/hacker" online:online_mode cripple:0];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        // Negative
        result = [_helper validateAuthentication:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0x0001];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateAuthentication:auth_possession_knowledge data:data method:get_method uriId:@"/hello/hacker" online:online_mode cripple:0x0010];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateAuthentication:auth_possession data:data method:get_method uriId:@"/hello/from/test" online:online_mode cripple:0x0100];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateAuthentication:auth_possession_knowledge data:data method:@"POST" uriId:@"/hello/from/test" online:online_mode cripple:0x1000];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
    }
    
    // Do more valid signatures. Count is important, due to fact that we have 8-bit local counter since V3.1
    for (int i = 1; i < 264; i++) {
        result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            id<PowerAuthOperationTask> task = [_sdk testCorePassword:auth.password callback:^(NSError * error) {
                [waiting reportCompletion:@(error == nil)];
            }];
            XCTAssertNotNil(task);
        }] boolValue];
        XCTAssertTrue(result);
        if ((i & 0x3f) == 1) {
            XCTAssertTrue(PowerAuthActivationState_Active == [_helper fetchActivationStatus].state);
        }
    }
    // One last status check
    XCTAssertTrue(PowerAuthActivationState_Active == [_helper fetchActivationStatus].state);
}

- (void) testCustomOfflineAuthCode
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates offline signatures with custom length.
    //

    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithFakeBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    NSUInteger componentLength = _sdk.configuration.offlineAuthenticationCodeComponentLength;
    XCTAssertNotEqual(8, componentLength);
    NSString * nonce = @"QVZlcnlDbGV2ZXJOb25jZQ==";
    
    // possession + knowledge
    NSString * code = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk offlineAuthenticationCodeWithAuthentication:_helper.authPossessionWithKnowledge uriId:@"/some/uriId" body:nil nonce:nonce callback:^(NSString * _Nullable authenticationCode, NSError * _Nullable error) {
            [waiting reportCompletion:authenticationCode];
        }];
    }];
    XCTAssertNotNil(code);
    XCTAssertEqual(componentLength*2+1, code.length);
    NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/some/uriId" nonce:nonce data:nil];
    PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineAuthCode:activation.activationData.activationId
                                                                                     data:normalized_data
                                                                                 authCode:code
                                                                            allowBiometry:NO
                                                                          componentLength:componentLength];
    XCTAssertTrue(response.signatureValid);
    
    // possession + biometry
    code = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk offlineAuthenticationCodeWithAuthentication:_helper.authPossessionWithBiometry uriId:@"/some/uriId" body:nil nonce:nonce callback:^(NSString * _Nullable authenticationCode, NSError * _Nullable error) {
            [waiting reportCompletion:authenticationCode];
        }];
    }];
    XCTAssertNotNil(code);
    XCTAssertEqual(componentLength*2+1, code.length);
    response = [_helper.testServerApi verifyOfflineAuthCode:activation.activationData.activationId
                                                       data:normalized_data
                                                   authCode:code
                                              allowBiometry:YES
                                            componentLength:componentLength];
    XCTAssertTrue(response.signatureValid);
}

- (void) testActivationStatus
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks whether SDK correctly maps server's activation status.
    // We're testing "ACTIVE", "BLOCKED", "REMOVED" states only, because other
    // states are automatically validated during the activation creation.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    PowerAuthTestServerAPI * testServerApi = _helper.testServerApi;
    PowerAuthActivationStatus * status;
    PATSSimpleActivationStatus * serverStatus;
    
    // 1) Initial state is "active"
    status = [_helper fetchActivationStatus];
    XCTAssertEqual(status.state, PowerAuthActivationState_Active);
    
    // 2) Block activation & fetch status
    serverStatus = [testServerApi blockActivation:activation.activationData.activationId];
    XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_BLOCKED);
    
    status = [_helper fetchActivationStatus];
    XCTAssertEqual(status.state, PowerAuthActivationState_Blocked);

    // 3) Unblock activation & fetch status
    serverStatus = [testServerApi unblockActivation:activation.activationId];
    XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_ACTIVE);
    
    status = [_helper fetchActivationStatus];
    XCTAssertEqual(status.state, PowerAuthActivationState_Active);
    
    // 4) Remove activation (which is also cleanup)
    [testServerApi removeActivation:activation.activationId];
    
    // 5) Fetch last status
    status = [_helper fetchActivationStatus];
    XCTAssertEqual(status.state, PowerAuthActivationState_Removed);
    
    // Test whether cached activation status is properly removed from memory
    XCTAssertNotNil(_sdk.lastFetchedActivationStatus);
    [_sdk removeActivationLocal];
    XCTAssertNil(_sdk.lastFetchedActivationStatus);
}

- (void) testActivationStatusConcurrent
{
    //
    // This test checks whether SDK correctly group getting activation status requests
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }

    __block PowerAuthActivationStatus * status1 = nil;
    __block PowerAuthActivationStatus * status2 = nil;
    __block PowerAuthActivationStatus * status3 = nil;
    AtomicCounter * counter = [[AtomicCounter alloc] init];
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task1, task2, task3, task4;
        task1 = [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            status1 = status;
            [counter incrementUpTo:3 completion:^{ [waiting reportCompletion:nil]; }];
        }];
        task4 = [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            XCTFail();
        }];
        task2 = [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            status2 = status;
            [counter incrementUpTo:3 completion:^{ [waiting reportCompletion:nil]; }];
        }];
        task3 = [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            status3 = status;
            [counter incrementUpTo:3 completion:^{ [waiting reportCompletion:nil]; }];
        }];
        [task4 cancel];
    }];
    XCTAssertNotNil(status1);
    XCTAssertNotNil(status2);
    XCTAssertNotNil(status3);
    XCTAssertTrue(status1 == status2);
    XCTAssertTrue(status1 == status3);
    XCTAssertTrue(status2 == status3);
    
    status1 = nil;
    status2 = nil;
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
            status1 = status;
            // Request for the status immediately from the callback
            [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status, NSError * error) {
                status2 = status;
                [waiting reportCompletion:nil];
            }];
        }];
    }];
    XCTAssertNotNil(status1);
    XCTAssertNotNil(status2);
    XCTAssertFalse(status1 == status2);
}

- (void) testActivationStatusFailCounters
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks whether SDK & Server correctly works
    // with fail / max fail counters after data signing.
    //
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PowerAuthAuthentication * just_possession = _helper.authPossession;
    
    // Correct AUTH with knowledge
    result = [_helper checkForCorePassword:auth.password];
    XCTAssertTrue(result);
    PowerAuthActivationStatus * status_after_correct = [_helper fetchActivationStatus];
    
    // Wrong AUTH with knowledge
    result = [_helper checkForPassword:@"MustBeWrong"];
    XCTAssertFalse(result); // result is invalid password
    PowerAuthActivationStatus * status_after_failure = [_helper fetchActivationStatus];
    XCTAssertTrue(status_after_correct.failCount + 1 == status_after_failure.failCount, @"failCount was not incremented or has wrong value");
    
    // Sign with possession factor
    NSData * data = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];
    NSArray * sig_nonce = [_helper calculateOnlineSignature:data method:@"POST" uriId:@"/hello/world" auth:just_possession];
    XCTAssertNotNil(sig_nonce);
    // Verify on the server (we're using SOAP because vanilla PA REST server doesn't have endpoint signed with possession
    NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/hello/world" nonce:sig_nonce[1] data:data];
    PATSVerifySignatureResponse * response = [_helper.testServerApi verifyAuthHeader:activation.activationId
                                                                                data:normalized_data
                                                                            authCode:sig_nonce[0]
                                                                             factors:@"POSSESSION"
                                                                             version:_helper.paVer];
    XCTAssertNotNil(response);
    XCTAssertTrue(response.signatureValid, @"Calculated signature is not valid");

    // Now check status after valid possession signature
    PowerAuthActivationStatus * status_after_possession = [_helper fetchActivationStatus];
    XCTAssertTrue(status_after_possession.failCount == status_after_failure.failCount, @"failCount should not change after valid possession factor");
    
    // Now try valid password
    // Fail attempt
    result = [_helper checkForCorePassword:auth.password];
    XCTAssertTrue(result);
    status_after_correct = [_helper fetchActivationStatus];
    XCTAssertNotNil(status_after_correct);
    XCTAssertTrue(status_after_correct.failCount == 0, "Fail counter was not reset to zero");
}

- (void) testActivationStatusMaxFailAttempts
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates maximum number failed of auth. attempts
    //
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
    // Correct AUTH with knowledge
    result = [_helper checkForCorePassword:auth.password];
    XCTAssertTrue(result);
    PowerAuthActivationStatus * status_after_correct = [_helper fetchActivationStatus];
    PowerAuthActivationStatus * after = status_after_correct;
    
    XCTAssertTrue(status_after_correct.failCount == 0);
    UInt32 count = status_after_correct.maxFailCount;
    for (UInt32 i = 1; i <= count; i++) {
        PowerAuthActivationStatus * before = after;
        XCTAssertNotNil(before);
        result = [_helper checkForPassword:@"MustBeWrong"];
        XCTAssertFalse(result); // result is invalid password
        after = [_helper fetchActivationStatus];
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
}

#define CTR_LOOKAHEAD 20    // Default constant on the server

- (void) testCounterSync_ClientIsAhead
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates whether Mobile SDK proactively synchronize counter
    // on the server, when local counter is slightly ahead to server's.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PowerAuthActivationStatus * status;
    // Positive
    for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
        // Just calculate signature on the client. This step simulates a network connection failure.
        PowerAuthHttpHeader * header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil error:NULL];
        XCTAssertNotNil(header);
        if ((i % 4) == 0) {
            // Every 4th signature calculation try to get the status
            status = [_helper fetchActivationStatus];
            XCTAssertNotNil(status);
            // Everything should be OK, because getting the status fires signature validation internally.
            XCTAssertEqual(status.state, PowerAuthActivationState_Active);
        }
    }
    status = [_helper fetchActivationStatus];
    XCTAssertNotNil(status);
    XCTAssertEqual(status.state, PowerAuthActivationState_Active);
    
    // Negative
    // Now try to calculate too many signatures that server will never catch
    for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
        // Just calculate signature on the client. This step simulates a network connection failure.
        PowerAuthHttpHeader * header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil  error:NULL];
        XCTAssertNotNil(header);
    }
    
    // Now get the status. It should be a deadlocked.
    status = [_helper fetchActivationStatus];
    XCTAssertNotNil(status);
    XCTAssertEqual(status.state, PowerAuthActivationState_Deadlock);
}

- (void) testCounterSync_ServerIsAhead
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates whether Mobile SDK is able to catch
    // server's counter if server is slightly ahead.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PowerAuthActivationStatus * status;

    // Positive
    NSData * data_to_sign = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];

    // Just calculate signature on the server.
    // This is a little bit tricky, because we need to calculate a valid signature, to move server's counter forward. To do that,
    // we have to calculate also a local signature, but that moves also local counter forward.
    // To trick the system, we need to keep old persistent data and restore it later.
    NSData * previous_state = [_helper sessionCoreSerializedState];
    for (int i = 0; i < CTR_LOOKAHEAD/2; i++) {
        NSString * local_signature = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            [_sdk offlineAuthenticationCodeWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" callback:^(NSString * _Nullable authenticationCode, NSError * _Nullable error) {
                [waiting reportCompletion:authenticationCode];
            }];
        }];
        NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
        PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineAuthCode:_sdk.activationIdentifier
                                                                                         data:normalized_data
                                                                                     authCode:local_signature
                                                                                allowBiometry:NO
                                                                              componentLength:0];
        XCTAssertNotNil(response, @"Online response must be received");
        XCTAssertTrue(response.signatureValid);
    }
    // Rollback counter to some previous state.
    [_helper sessionCoreDeserializeState:previous_state];
    // Fetch the status. This should move local counter forward, so the next calculation will succeed.
    status = [_helper fetchActivationStatus];
    XCTAssertNotNil(status);
    XCTAssertEqual(status.state, PowerAuthActivationState_Active);
    BOOL password_result = [_helper checkForCorePassword:auth.password];
    XCTAssertTrue(password_result);
    
    // Negative
    // Now try to calculate too many signatures that client will never catch the server.
    previous_state = [_helper sessionCoreSerializedState];
    for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
        NSString * local_signature = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            [_sdk offlineAuthenticationCodeWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" callback:^(NSString * _Nullable authenticationCode, NSError * _Nullable error) {
                [waiting reportCompletion:authenticationCode];
            }];
        }];
        NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
        PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineAuthCode:_sdk.activationIdentifier
                                                                                         data:normalized_data
                                                                                     authCode:local_signature
                                                                                allowBiometry:NO
                                                                              componentLength:0];
        XCTAssertNotNil(response, @"Online response must be received");
        XCTAssertTrue(response.signatureValid);
    }
    // Rollback counter to some previous state.
    [_helper sessionCoreDeserializeState:previous_state];
    
    // Now get the status. It should be a deadlocked.
    status = [_helper fetchActivationStatus];
    XCTAssertNotNil(status);
    XCTAssertEqual(status.state, PowerAuthActivationState_Deadlock);
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
    
    PowerAuthTestServerAPI * testServerApi = _helper.testServerApi;
    PowerAuthTestServerConfig * testServerConfig = _helper.testServerConfig;
    
    // 1) At first, we have to create an application version which is always supported.
    [testServerApi createApplicationVersionIfDoesntExist:@"test-supported"];
    
    // 2) Unsupport application version, created in
    NSString * versionIdentifier = testServerApi.appVersion.applicationVersionId;
    BOOL statusResult = [testServerApi unsupportApplicationVersion:versionIdentifier];
    XCTAssertTrue(statusResult, @"Unable to change application status to 'unsupported'");
    if (!statusResult) {
        return;
    }
    
    // OK, application is not supported, try to create an activation
    
    // 3) SERVER: initialize an activation on server (this is typically implemented in the internet banking application)
    PATSInitActivationResponse * activationData = [testServerApi initializeActivation:testServerConfig.userIdentifier];
    NSString * activationCode = [activationData activationCodeWithSignature];
    
    __block NSString * activationFingerprint = nil;
    
    // 4) CLIENT: Start activation on client's side
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        
        NSString * activationName = testServerConfig.userActivationName;
        id<PowerAuthOperationTask> task = [_sdk createActivationWithName:activationName activationCode:activationCode callback:^(PowerAuthActivationResult * result, NSError * error) {
            activationFingerprint = result.activationFingerprint;
            reportedError = error;
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
        
    }] boolValue];
    XCTAssertFalse(result, @"Activation on client side did not fail.");
    
    // 5) Set application back to supported
    statusResult = [testServerApi supportApplicationVersion:versionIdentifier];
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
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    // 1) Let's block activation
    PATSSimpleActivationStatus * serverStatus = [_helper.testServerApi blockActivation:activation.activationId];
    XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_BLOCKED);
    
    // 2) At first, use invalid password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk testPassword:@"MustBeWrong" callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertFalse(result); // Must not pass. Activation is blocked
    
    // 3) Now use a valid password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk testCorePassword:auth.password callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertFalse(result); // Must not pass. Activation is blocked
    
    // 4) Unblock
    serverStatus = [_helper.testServerApi unblockActivation:activation.activationId];
    XCTAssertEqual(serverStatus.activationStatusEnum, PATSActivationStatus_ACTIVE);
    
    // 5) Test password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk testCorePassword:auth.password callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertTrue(result);  // Must pass, valid password, activation is active again
}

- (void) testCallToCreateActivationInWrongState
{
    CHECK_TEST_CONFIG();
    
    //
    // This validates various API misuses.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    XCTAssertTrue(_sdk.hasValidActivation);
    
    NSError * err = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk persistActivationWithPassword:@"1234" callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:error];
        }];
    }];
    XCTAssertNotNil(err);
    XCTAssertEqual(PowerAuthErrorCode_InvalidActivationState, err.powerAuthErrorCode);
    
    XCTAssertTrue(_sdk.hasValidActivation);
    
    err = nil;
    PowerAuthActivation * newActivationRequest = [PowerAuthActivation activationWithActivationCode:@"MMMMM-MMMMM-MMMMM-MUTOA" name:nil error:&err];
    XCTAssertNil(err);
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk createActivation:newActivationRequest callback:^(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error) {
            XCTAssertNil(result);
            XCTAssertNotNil(error);
            XCTAssertEqual(PowerAuthErrorCode_InvalidActivationState, error.powerAuthErrorCode);
            [waiting reportCompletion:nil];
        }];
    }];
    XCTAssertTrue(_sdk.hasValidActivation);
}

// MARK: - EEK
// TODO: eek
/*
- (void) testExternalEncryptionKey
{
    CHECK_TEST_CONFIG();
    
    //
    // This validates EEK usage.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    PowerAuthCoreData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    
    NSError * error = nil;
    BOOL result = [_sdk addExternalEncryptionKey:eek error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    result = [_sdk removeExternalEncryptionKey:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
}

- (void) testEEKFromConfiguration
{
    CHECK_TEST_CONFIG();
        
    //
    // This validates EEK usage from the beginning.
    //
    
    PowerAuthCoreData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    PowerAuthConfiguration * newConfig = [_sdk.configuration copy];
    newConfig.externalEncryptionKey = eek;
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:newConfig biometricConfiguration:nil keychainConfiguration:nil clientConfiguration:nil];
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    NSError * error = nil;
    BOOL result = [_sdk removeExternalEncryptionKey:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);

    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
}

- (void) testSetEEKBeforeActivation
{
    CHECK_TEST_CONFIG();
    
    //
    // This validates when EEK is set before activation is created.
    //
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);
    PowerAuthCoreData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    NSError * error = nil;
    BOOL result = [_sdk setExternalEncryptionKey:eek error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    result = [_sdk removeExternalEncryptionKey:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);

    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
}

- (void) testSetEEKAfterActivation
{
    CHECK_TEST_CONFIG();
    
    //
    // This validates when EEK is set after activation is created.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    PowerAuthCoreData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    
    NSError * error = nil;
    BOOL result = [_sdk addExternalEncryptionKey:eek error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);

    // Now re-instantiate SDK and try to set EEK manually
    PowerAuthConfiguration * newConfig = [_sdk.configuration copy];
    newConfig.externalEncryptionKey = nil;
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:newConfig biometricConfiguration:nil keychainConfiguration:nil clientConfiguration:nil];
    XCTAssertFalse(_sdk.hasExternalEncryptionKey);
    // Activation status should work
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertEqual(PowerAuthActivationState_Active, status.state);
    // Now set EEK
    result = [_sdk setExternalEncryptionKey:eek error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
}
*/

// MARK: - Request synchronization

- (void) testCancelEnqueuedHttpOperation
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates whether cancelation of enqueued, but not executed yet
    // HTTP request doesn't lead to crash. See bug #435 for more details.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk testCorePassword:activation.credentials.password callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
        id<PowerAuthOperationTask> task = [_sdk testCorePassword:activation.credentials.password callback:^(NSError * _Nullable error) {
            XCTFail();
        }];
        [task cancel];
    }];
}

// MARK: - Biometry

- (void) testBiometrySignatureWhenNotConfigured
{
    CHECK_TEST_CONFIG();

#if defined(PA2_BIOMETRY_SUPPORT)
    BOOL supportsBiometry = YES;
#else
    BOOL supportsBiometry = NO;
#endif
    
    //
    // This test validates that signing with biometry doesn't work when
    // no biometry is configured.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    PowerAuthAuthentication * authentication;
    PowerAuthHttpHeader * header;
    
    NSError * error = nil;
    authentication = [PowerAuthAuthentication possessionWithBiometry];
    header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
    XCTAssertNil(header);
    if (supportsBiometry) {
        XCTAssertEqual(PowerAuthErrorCode_BiometryFailed, error.powerAuthErrorCode);
    } else {
        XCTAssertEqual(PowerAuthErrorCode_BiometryNotAvailable, error.powerAuthErrorCode);
    }
    
    error = nil;
    authentication = [PowerAuthAuthentication possessionWithBiometryPrompt:@"Authenticate with biometry"];
    header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
    XCTAssertNil(header);
    
    if (supportsBiometry) {
        XCTAssertEqual(PowerAuthErrorCode_BiometryFailed, error.powerAuthErrorCode);
    } else {
        XCTAssertEqual(PowerAuthErrorCode_BiometryNotAvailable, error.powerAuthErrorCode);
    }
}

#if defined(PA2_BIOMETRY_SUPPORT)

- (void) testCreateActivationWithBiometry
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates whether it's possible to create activation with biometry factor set.
    //
    
    CHECK_BIOMETRY();
    
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    XCTAssertTrue([_sdk hasBiometryFactor]);
}

- (void) testCreateActivationWithExternalBiometry
{
    CHECK_TEST_CONFIG();
        
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithFakeBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    XCTAssertTrue([_sdk hasBiometryFactor]);
    
    PowerAuthAuthentication * auth = _helper.authPossessionWithBiometry;

    // Remove activation from the server
    NSError * removeError = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk removeActivationWithAuthentication:auth callback:^(NSError * error) {
            [waiting reportCompletion:error];
        }];
        XCTAssertNotNil(task);
    }];
    XCTAssertNil(removeError);
    XCTAssertNil(_sdk.activationIdentifier);
}

- (void) testAddingBiometryFactor
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates whether it's possible to add biometry factor later.
    //
    
    CHECK_BIOMETRY();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    XCTAssertFalse([_sdk hasBiometryFactor]);
    PowerAuthCoreData * newBiometryKek = [PowerAuthCoreCryptoUtils randomCoreData:_sdk.currentAlgorithm == PowerAuthAlgorithm_LEGACY_P256 ? 16 : 32];
    PowerAuthAuthentication * newBiometryAuth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:newBiometryKek customPossessionKey:nil];
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:63] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk addBiometryFactorWithCorePassword:activation.credentials.password customBiometryKek:newBiometryKek callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertTrue([_sdk hasBiometryFactor]);

    
    BOOL result = [_helper validateAuthentication:newBiometryAuth
                                             data:randomData
                                           method:@"POST"
                                            uriId:@"/hello/biohacker"
                                           online:YES
                                          cripple:0];
    XCTAssertTrue(result);
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk removeBiometryFactorWithCallback:^(NSError * error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertFalse([_sdk hasBiometryFactor]);
    
    result = [_helper validateAuthentication:newBiometryAuth
                                        data:randomData
                                      method:@"POST"
                                       uriId:@"/hello/biohacker"
                                      online:YES
                                     cripple:0];
    XCTAssertFalse(result);

    newBiometryKek = [PowerAuthCoreCryptoUtils randomCoreData:_sdk.currentAlgorithm == PowerAuthAlgorithm_LEGACY_P256 ? 16 : 32];
    newBiometryAuth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:newBiometryKek customPossessionKey:nil];
    randomData = [[[PowerAuthCoreCryptoUtils randomBytes:63] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk addBiometryFactorWithPassword:activation.credentials.password.extractedPassword customBiometryKek:newBiometryKek callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertTrue([_sdk hasBiometryFactor]);
    
    result = [_helper validateAuthentication:newBiometryAuth
                                             data:randomData
                                           method:@"POST"
                                            uriId:@"/hello/biohacker"
                                           online:YES
                                          cripple:0];
    XCTAssertTrue(result);
}

- (void) testWithWrongLAContext
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates that LAContext with wrong configuration should not work.
    //
    
    CHECK_BIOMETRY();
    
    // Use context with `interactionNotAllowed`
    LAContext * context = [[LAContext alloc] init];
    context.interactionNotAllowed = YES;
    
    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    XCTAssertTrue([_sdk hasBiometryFactor]);

    PowerAuthAuthentication * authentication = [PowerAuthAuthentication possessionWithBiometryContext:context];
    NSError * error = nil;
    PowerAuthHttpHeader * header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
    XCTAssertNil(header);
    XCTAssertEqual(PowerAuthErrorCode_BiometryFailed, error.powerAuthErrorCode);
}

#endif // PA2_BIOMETRY_SUPPORT

- (void) testUserInfo
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates that the User Info claims are stored correctly after activation
    // and properly updated after fetching new User Info from the server.
    //
    
    // Test the `lastFetchedUserInfo` is nil before the data are fetched.
    XCTAssertFalse(_sdk.hasValidActivation);
    XCTAssertNil(_sdk.lastFetchedUserInfo);
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    // Test that the User Info from the Activation response is stored as last fetched.
    PowerAuthUserInfo * infoFromActivation = activation.activationResult.userInfo;
    NSString * userId = _helper.testServerConfig.userIdentifier;
    XCTAssertNotNil(_sdk.lastFetchedUserInfo);
    XCTAssertNotNil(infoFromActivation);
    XCTAssertEqualObjects(userId, _sdk.lastFetchedUserInfo.subject);
    XCTAssertEqualObjects(userId, infoFromActivation.subject);
    XCTAssertEqualObjects(infoFromActivation.allClaims[@"jti"], _sdk.lastFetchedUserInfo.allClaims[@"jti"]);
    
    // Fetch fresh User Info.
    PowerAuthUserInfo * info = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchUserInfo:^(PowerAuthUserInfo * userInfo, NSError * error) {
            XCTAssertNil(error);
            [waiting reportCompletion:userInfo];
        }];
    }];
    XCTAssertNotNil(info);
    XCTAssertEqualObjects(info.subject, _helper.testServerConfig.userIdentifier);
    
    // Check the last fetched User Info was updated (i.e. JWT ID was changed).
    XCTAssertNotEqualObjects(info.allClaims[@"jti"], infoFromActivation.allClaims[@"jti"]);
    XCTAssertEqualObjects(info.allClaims[@"jti"], _sdk.lastFetchedUserInfo.allClaims[@"jti"]);
}

#pragma mark - Digital signatures

- (void) testExportDevicePublicKey
{
    CHECK_TEST_CONFIG();
    
    NSError * error = nil;
    NSArray<PowerAuthDevicePublicKeyData*>* keys = [_sdk exportDevicePublicKeysToFormat:PowerAuthDevicePublicKeyFormat_Der error:&error];
    XCTAssertNil(keys);
    XCTAssertNotNil(error);
    XCTAssertEqual(PowerAuthErrorCode_MissingActivation, error.powerAuthErrorCode);
    error = nil;
    keys = [_sdk exportDevicePublicKeysToFormat:PowerAuthDevicePublicKeyFormat_Raw error:&error];
    XCTAssertNil(keys);
    XCTAssertNotNil(error);
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    NSDictionary<NSNumber*, NSString*>* keyMapping;
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_LEGACY_P256:
            keyMapping = @{ @(PowerAuthSignatureKeyType_EC) : @"P-256" };
            break;
        case PowerAuthAlgorithm_EC_P384:
            keyMapping = @{ @(PowerAuthSignatureKeyType_EC) : @"P-384" };
            break;
        case PowerAuthAlgorithm_EC_P384_ML_L3:
            keyMapping = @{ @(PowerAuthSignatureKeyType_EC) : @"P-384", @(PowerAuthSignatureKeyType_ML_DSA) : @"ML-DSA-65" };
            break;
        case PowerAuthAlgorithm_EC_P384_ML_L5:
            keyMapping = @{ @(PowerAuthSignatureKeyType_EC) : @"P-384", @(PowerAuthSignatureKeyType_ML_DSA) : @"ML-DSA-87" };
            break;
        default:
            XCTFail(@"Unsupported algorithm");
            return;
    }
    error = nil;
    keys = [_sdk exportDevicePublicKeysToFormat:PowerAuthDevicePublicKeyFormat_Der error:&error];
    XCTAssertNotNil(keys);
    XCTAssertNil(error);
    __block NSUInteger matched = 0;
    [keys enumerateObjectsUsingBlock:^(PowerAuthDevicePublicKeyData * _Nonnull keyData, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString * expectedKeyAlgorithm = keyMapping[@(keyData.keyType)];
        if (!expectedKeyAlgorithm) {
            XCTFail(@"Key type %@ not supported", @(keyData.keyType));
            return;
        }
        XCTAssertEqualObjects(expectedKeyAlgorithm, keyData.keyAlgorithm);
        matched++;
    }];
    XCTAssertEqual(matched, keyMapping.count);
    
    error = nil;
    keys = [_sdk exportDevicePublicKeysToFormat:PowerAuthDevicePublicKeyFormat_Raw error:&error];
    XCTAssertNotNil(keys);
    XCTAssertNil(error);
    matched = 0;
    [keys enumerateObjectsUsingBlock:^(PowerAuthDevicePublicKeyData * _Nonnull keyData, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString * expectedKeyAlgorithm = keyMapping[@(keyData.keyType)];
        if (!expectedKeyAlgorithm) {
            XCTFail(@"Key type %@ not supported", @(keyData.keyType));
            return;
        }
        XCTAssertEqualObjects(expectedKeyAlgorithm, keyData.keyAlgorithm);
        matched++;
    }];
    XCTAssertEqual(matched, keyMapping.count);
}

- (void) testActivationCodeSignature
{
    CHECK_TEST_CONFIG();
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    NSData * activationCodeData = [activation.activationData.activationCode dataUsingEncoding:NSUTF8StringEncoding];
        
    NSError * error = nil;
    BOOL success = NO;
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_LEGACY_P256:
            XCTAssertNotNil(activation.activationData.activationSignature);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignature options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            break;

        case PowerAuthAlgorithm_EC_P384_ML_L3:
            XCTAssertNotNil(activation.activationData.activationSignatureMldsa65);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignatureMldsa65 options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_ML_DSA
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            XCTAssertNotNil(activation.activationData.activationSignatureEcdsa);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignatureEcdsa options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            break;
            
        case PowerAuthAlgorithm_EC_P384_ML_L5:
            XCTAssertNotNil(activation.activationData.activationSignatureMldsa87);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignatureMldsa87 options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_ML_DSA
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            XCTAssertNotNil(activation.activationData.activationSignatureEcdsa);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignatureEcdsa options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            break;
            
        case PowerAuthAlgorithm_EC_P384:
            XCTAssertNotNil(activation.activationData.activationSignatureEcdsa);
            error = nil;
            success = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:activation.activationData.activationSignatureEcdsa options:0]
                                        signedData:activationCodeData
                                     keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                             error:&error];
            XCTAssertTrue(success);
            XCTAssertNil(error);
            break;
            
        default:
            XCTFail(@"Unsupported algorithm");
            break;
    }
}

- (void) testVerifyOfflineServerSignedData
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks whether SDK can verify data signed by server's master key
    //
    BOOL result;
    NSError *error = nil;
    PATSOfflineSignaturePayload *payload;
    {
        // Verify data signed with master key (non-personalized)
        NSString * dataForSigning = @"All your money are belong to us!";
        payload = [_helper.testServerApi createNonPersonalizedOfflineSignaturePayload:_helper.testServerApi.appDetail.applicationId data:dataForSigning];
        XCTAssertNotNil(payload);
        XCTAssertTrue([payload.parsedData isEqualToString:dataForSigning]);
        XCTAssertTrue([payload.parsedSigningKey isEqualToString:@"0"]);
        
        NSData * signedData = [payload.parsedSignedData dataUsingEncoding:NSUTF8StringEncoding];
        result = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:payload.parsedSignature options:0]
                                   signedData:signedData
                                keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                        error:&error];
        XCTAssertTrue(result);
        XCTAssertNil(error);
    }
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    {
        // Retry after activation creation
        // Verify data signed with master key (non-personalized)
        NSString * dataForSigning = @"All your money are belong to us!";
        payload = [_helper.testServerApi createNonPersonalizedOfflineSignaturePayload:_helper.testServerApi.appDetail.applicationId data:dataForSigning];
        XCTAssertNotNil(payload);
        XCTAssertTrue([payload.parsedData isEqualToString:dataForSigning]);
        XCTAssertTrue([payload.parsedSigningKey isEqualToString:@"0"]);
        
        NSData * signedData = [payload.parsedSignedData dataUsingEncoding:NSUTF8StringEncoding];
        result = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:payload.parsedSignature options:0]
                                   signedData:signedData
                                keyIdentifier:PowerAuthSignatureKeyId_Master_EC
                                        error:&error];
        XCTAssertTrue(result);
        XCTAssertNil(error);
    }
    {
        // Verify data signed with server key (personalized)
        NSString * expectedSigningKey;
        PowerAuthSignatureKeyId signingKeyId;
        if (_sdk.currentAlgorithm == PowerAuthAlgorithm_LEGACY_P256) {
            // V3 uses SERVER_EC key for signature
            expectedSigningKey = @"1";
            signingKeyId = PowerAuthSignatureKeyId_Server_EC;
        } else {
            // V4 uses MAC key
            expectedSigningKey = @"2";
            signingKeyId = PowerAuthSignatureKeyId_MacPersonalized;
        }
        NSString * dataForSigning = @"All your money are belong to us!";
        payload = [_helper.testServerApi createPersonalizedOfflineSignaturePayload:activation.activationId data:dataForSigning];
        XCTAssertNotNil(payload);
        XCTAssertTrue([payload.parsedData isEqualToString:dataForSigning]);
        XCTAssertTrue([payload.parsedSigningKey isEqualToString:expectedSigningKey]);
        
        NSData * signedData = [payload.parsedSignedData dataUsingEncoding:NSUTF8StringEncoding];
        error = nil;
        result = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:payload.parsedSignature options:0]
                                   signedData:signedData
                                keyIdentifier:signingKeyId
                                        error:&error];
        XCTAssertTrue(result);
        XCTAssertNil(error);
        // Bad data
        NSMutableData * badData = [signedData mutableCopy];
        char * dataPtr = badData.mutableBytes;
        dataPtr[0]++;
        error = nil;
        result = [_sdk verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:payload.parsedSignature options:0]
                                   signedData:badData
                                keyIdentifier:signingKeyId
                                        error:&error];
        XCTAssertFalse(result);
        XCTAssertEqual(PowerAuthErrorCode_WrongSignature, error.powerAuthErrorCode);
    }
    
    // Well, we have a data for offline signature, so let's try to verify it.
    NSString * uriId = @"/operation/authorize/offline";
    NSData * body = [payload.parsedData dataUsingEncoding:NSUTF8StringEncoding];
    NSString * nonce = payload.nonce;

    PowerAuthAuthentication * sign_auth = [auth copy];
    NSString * local_signature = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk offlineAuthenticationCodeWithAuthentication:sign_auth uriId:uriId body:body nonce:nonce callback:^(NSString * _Nullable authenticationCode, NSError * _Nullable error) {
            [waiting reportCompletion:authenticationCode];
        }];
    }];
    XCTAssertNotNil(local_signature);

    NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:uriId nonce:nonce data:body];
    XCTAssertNotNil(normalized_data);
    PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineAuthCode:activation.activationData.activationId
                                                                                     data:normalized_data
                                                                                 authCode:local_signature
                                                                            allowBiometry:NO
                                                                          componentLength:0];
    XCTAssertTrue(response.signatureValid);
}

- (void) verifyDataSignedWithSignatureKeyId:(PowerAuthSignatureKeyId)signatureKeyId
                              signatureType:(NSString*)signatureType
                             authentication:(PowerAuthAuthentication*)authentication
                                 shouldPass:(BOOL)shouldPass
{
    NSData * dataForSigning = [@"This is a very sensitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];

    // 1) At first, calculate signature
    __block NSData * resultSignature = nil;
    __block NSError * resultError = nil;
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk calculateDigitalSignature:authentication
                                                               dataToSign:dataForSigning
                                                            keyIdentifier:signatureKeyId
                                                                 callback:^(NSData * _Nullable signature, NSError * _Nullable error) {
            resultSignature = signature;
            resultError = error;
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        if (shouldPass) {
            XCTAssertNotNil(task);
        }
    }] boolValue];
    XCTAssertEqual(shouldPass, result);
    if (shouldPass) {
        // 2) Verify signature on the server
        result = [_helper.testServerApi verifyDsaSignature:_sdk.activationIdentifier
                                                      data:dataForSigning
                                                 signature:resultSignature
                                           signatureFormat:@"DER"
                                             signatureType:signatureType];
        XCTAssertTrue(result);
        // 3) Verify locally
        resultError = nil;
        result = [_sdk verifyDigitalSignature:resultSignature
                                   signedData:dataForSigning
                                keyIdentifier:signatureKeyId
                                        error:&resultError];
        XCTAssertTrue(result);
        XCTAssertNil(resultError);
    }
}

- (void) testSignDataWithDevicePrivateKey
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks data signing with device's private key.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_EC_P384_ML_L5:
        case PowerAuthAlgorithm_EC_P384_ML_L3:
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device signatureType:@"ECDSA" authentication:auth shouldPass:NO];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC signatureType:@"ECDSA" authentication:auth shouldPass:YES];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA signatureType:@"MLDSA" authentication:auth shouldPass:YES];
            break;
        case PowerAuthAlgorithm_EC_P384:
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device signatureType:@"ECDSA" authentication:auth shouldPass:YES];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC signatureType:@"ECDSA" authentication:auth shouldPass:YES];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA signatureType:@"MLDSA" authentication:auth shouldPass:NO];
            break;
        case PowerAuthAlgorithm_LEGACY_P256:
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device signatureType:@"ECDSA" authentication:auth shouldPass:YES];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC signatureType:@"ECDSA" authentication:auth shouldPass:YES];
            [self verifyDataSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA signatureType:@"MLDSA" authentication:auth shouldPass:NO];
            break;
    }
}

- (void) testVerifyServerSignedData
{
    CHECK_TEST_CONFIG();
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    NSData * dataForSigning = [@"This is a very sensitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];
    NSData * badSignedData  = [@"This is a very sEnsitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary * signatures = [_helper.testServerApi createDsaSignature:_sdk.activationIdentifier data:dataForSigning];
    NSData * ecdsa = [[NSData alloc] initWithBase64EncodedString:signatures[@"ecdsa"] options:0];
    NSData * mldsa = signatures[@"mldsa"] ? [[NSData alloc] initWithBase64EncodedString:signatures[@"mldsa"] options:0] : nil;
    BOOL result;
    NSError * error;
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_LEGACY_P256:
        case PowerAuthAlgorithm_EC_P384:
            XCTAssertNotNil(ecdsa);
            XCTAssertNil(mldsa);
            result = [_sdk verifyDigitalSignature:ecdsa signedData:dataForSigning keyIdentifier:PowerAuthSignatureKeyId_Server_EC error:&error];
            XCTAssertTrue(result);
            XCTAssertNil(error);
            // bad data
            error = nil;
            result = [_sdk verifyDigitalSignature:ecdsa signedData:badSignedData keyIdentifier:PowerAuthSignatureKeyId_Server_EC error:&error];
            XCTAssertFalse(result);
            XCTAssertEqual(PowerAuthErrorCode_WrongSignature, error.powerAuthErrorCode);
            break;
        case PowerAuthCoreAlgorithm_EC_P384_ML_L5:
        case PowerAuthCoreAlgorithm_EC_P384_ML_L3:
            XCTAssertNotNil(ecdsa);
            XCTAssertNotNil(mldsa);
            result = [_sdk verifyDigitalSignature:ecdsa signedData:dataForSigning keyIdentifier:PowerAuthSignatureKeyId_Server_EC error:&error];
            XCTAssertTrue(result);
            XCTAssertNil(error);
            error = nil;
            result = [_sdk verifyDigitalSignature:mldsa signedData:dataForSigning keyIdentifier:PowerAuthSignatureKeyId_Server_ML_DSA error:&error];
            XCTAssertTrue(result);
            XCTAssertNil(error);
            // bad data
            error = nil;
            result = [_sdk verifyDigitalSignature:ecdsa signedData:badSignedData keyIdentifier:PowerAuthSignatureKeyId_Server_EC error:&error];
            XCTAssertFalse(result);
            XCTAssertEqual(PowerAuthErrorCode_WrongSignature, error.powerAuthErrorCode);
            error = nil;
            result = [_sdk verifyDigitalSignature:mldsa signedData:badSignedData keyIdentifier:PowerAuthSignatureKeyId_Server_ML_DSA error:&error];
            XCTAssertFalse(result);
            XCTAssertEqual(PowerAuthErrorCode_WrongSignature, error.powerAuthErrorCode);
            break;
        default:
            XCTFail(@"Unsupported algorithm");
            break;
    }
}

- (void) verifyJwsServerSignedData:(PowerAuthSignatureKeyId)signatureKeyId
                     signatureType:(NSString*)signatureType
                       compactForm:(BOOL)compactForm
                            strict:(BOOL)strict
                        shouldPass:(BOOL)shouldPass
{
    NSData * dataForSigning = [@"This is a very sensitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];
    NSString * jws = [_helper.testServerApi createJwtSignature:_sdk.activationIdentifier
                                                          data:dataForSigning
                                                       compact:compactForm
                                                 signatureType:signatureType];
    NSError * error = nil;
    BOOL result = [_sdk verifyJwsSignature:jws
                                   compact:compactForm
                                    strict:strict
                             keyIdentifier:signatureKeyId
                                     error:&error];
    if (shouldPass) {
        XCTAssertTrue(result);
        XCTAssertNil(error);
    } else {
        XCTAssertFalse(result);
        //XCTAssertNotNil(error);   // No error is reported
    }
}

- (void) testVerifyJwsServerSignedData
{
    CHECK_TEST_CONFIG();
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_LEGACY_P256:
            // Not available
            break;
        case PowerAuthAlgorithm_EC_P384:
            // JWT
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:YES strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:YES strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:YES strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:YES strict:NO  shouldPass:YES];
            // JWS
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:NO  strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:NO  strict:NO  shouldPass:YES];
            // JWT - hybrid (should work, there's only one key available)
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:YES strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:YES strict:NO  shouldPass:YES];
            // JWS - hybrid
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:NO  strict:NO  shouldPass:YES];
            break;
        case PowerAuthCoreAlgorithm_EC_P384_ML_L5:
        case PowerAuthCoreAlgorithm_EC_P384_ML_L3:
            // JWT - ecdsa
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:YES strict:YES shouldPass:NO]; // strict mode require all keys to satisfy
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:YES strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:YES strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:YES strict:NO  shouldPass:YES];
            // JWT - mldsa
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"MLDSA" compactForm:YES strict:YES shouldPass:NO]; // strict mode require all keys to satisfy
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_ML_DSA signatureType:@"MLDSA" compactForm:YES strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"MLDSA" compactForm:YES strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_ML_DSA signatureType:@"MLDSA" compactForm:YES strict:NO  shouldPass:YES];
            // JWS - ecdsa
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:NO  strict:YES shouldPass:NO]; // strict mode require all keys to satisfy
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"ECDSA" compactForm:NO  strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_EC     signatureType:@"ECDSA" compactForm:NO  strict:NO  shouldPass:YES];
            // JWS - mldsa
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"MLDSA" compactForm:NO  strict:YES shouldPass:NO]; // strict mode require all keys to satisfy
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_ML_DSA signatureType:@"MLDSA" compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:@"MLDSA" compactForm:NO  strict:NO  shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server_ML_DSA signatureType:@"MLDSA" compactForm:NO  strict:NO  shouldPass:YES];
            // JWS - hybrid
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:NO  strict:YES shouldPass:YES];
            [self verifyJwsServerSignedData:PowerAuthSignatureKeyId_Server        signatureType:nil      compactForm:NO  strict:NO  shouldPass:YES];
            break;
        default:
            XCTFail(@"Unsupported algorithm");
            break;
    }

}

- (void) verifyJwtSignedWithSignatureKeyId:(PowerAuthSignatureKeyId)signatureKeyId
                               compactForm:(BOOL)compactForm
                                    strict:(BOOL)strict
                            authentication:(PowerAuthAuthentication*)authentication
                                shouldPass:(BOOL)shouldPass
{
    NSData * dataForSigning = [@"This is a very sensitive information and must be signed." dataUsingEncoding:NSUTF8StringEncoding];

    // 1) At first, calculate signature
    __block NSString * resultSignature = nil;
    __block NSError * resultError = nil;
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        
        id<PowerAuthOperationTask> task = [_sdk calculateJwsSignature:authentication
                                                           dataToSign:dataForSigning
                                                             dataType:nil
                                                              compact:compactForm
                                                        keyIdentifier:signatureKeyId
                                                             callback:^(NSString * _Nullable jws, NSError * _Nullable error) {
            resultSignature = jws;
            resultError = error;
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        if (shouldPass) {
            XCTAssertNotNil(task);
        }
    }] boolValue];
    XCTAssertEqual(shouldPass, result);
    if (result) {
        // 2) Verify signature on the server
        result = [_helper.testServerApi verifyJwtSignature:_sdk.activationIdentifier
                                                signedData:resultSignature
                                                   compact:compactForm];
        XCTAssertTrue(result);
        // 3) Verify locally
        resultError = nil;
        result = [_sdk verifyJwsSignature:resultSignature
                                  compact:compactForm
                                   strict:strict
                            keyIdentifier:signatureKeyId
                                    error:&resultError];
        if (shouldPass) {
            XCTAssertTrue(result);
            XCTAssertNil(resultError);
        } else {
            XCTAssertFalse(result);
            XCTAssertNotNil(resultError);
        }
    }
}

- (void) testJwsSignDataWithDevicePrivateKey
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks JWS data signing with device's private key.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    switch (_sdk.currentAlgorithm) {
        case PowerAuthAlgorithm_EC_P384_ML_L5:
        case PowerAuthAlgorithm_EC_P384_ML_L3:
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA compactForm:NO strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA compactForm:YES strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device compactForm:NO strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC compactForm:NO strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC compactForm:YES strict:YES authentication:auth shouldPass:YES];
            break;
        case PowerAuthAlgorithm_EC_P384:
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device compactForm:YES strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device compactForm:NO strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC compactForm:NO strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_EC compactForm:YES strict:YES authentication:auth shouldPass:YES];
            [self verifyJwtSignedWithSignatureKeyId:PowerAuthSignatureKeyId_Device_ML_DSA compactForm:NO strict:YES authentication:auth shouldPass:NO];
            break;
        case PowerAuthAlgorithm_LEGACY_P256:
            // API not supported on the server
            break;
    }
}

- (void) testJwtSignature
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    // Get JWT
    NSDictionary * originalClaims = @{@"sub": @"1234567890", @"name": @"John Doe", @"admin": @(YES)};
    NSString * jwt = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk calculateJwsSignature:_helper.authPossessionWithKnowledge
                         dataToSign:[NSJSONSerialization dataWithJSONObject:originalClaims options:0 error:nil]
                           dataType:@"JWT"
                            compact:YES
                      keyIdentifier:PowerAuthSignatureKeyId_Device_EC callback:^(NSString * _Nullable jws, NSError * _Nullable error) {
            [waiting reportCompletion:jws];
        }];
    }];
    NSError * error = nil;
    BOOL result = [_sdk verifyJwsSignature:jwt
                                   compact:YES
                                    strict:YES
                             keyIdentifier:PowerAuthSignatureKeyId_Device_EC
                                     error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    // Parse JWT and validate result
    XCTAssertNotNil(jwt);
    NSArray * jwtComponents = [jwt componentsSeparatedByString:@"."];
    XCTAssertEqual(3, jwtComponents.count);
    if (jwtComponents.count != 3) {
        return;
    }
    NSString * expectedAlg = _sdk.currentAlgorithm == PowerAuthAlgorithm_LEGACY_P256 ? @"ES256" : @"ES384";
    NSString * jwtHeader = jwtComponents[0];
    NSString * jwtClaims = jwtComponents[1];
    NSString * jwtSignature = jwtComponents[2];
    // Validate header
    NSData * jwtHeaderData = [[NSData alloc] initWithJwtEncodedString:jwtHeader];
    XCTAssertNotNil(jwtHeaderData);
    NSDictionary * headerObject = [NSJSONSerialization JSONObjectWithData:jwtHeaderData options:0 error:NULL];
    XCTAssertNotNil(headerObject);
    XCTAssertEqualObjects(expectedAlg, headerObject[@"alg"]);
    XCTAssertEqualObjects(@"JWT", headerObject[@"typ"]);
    // Validate claims
    NSData * jwtClaimsData = [[NSData alloc] initWithJwtEncodedString:jwtClaims];
    XCTAssertNotNil(jwtClaimsData);
    NSDictionary * claims = [NSJSONSerialization JSONObjectWithData:jwtClaimsData options:0 error:NULL];
    XCTAssertEqual(originalClaims.count, claims.count);
    [originalClaims enumerateKeysAndObjectsUsingBlock:^(id key, id  originalObj, BOOL * stop) {
        id obj = claims[key];
        XCTAssertEqualObjects(originalObj, obj);
    }];
    // Validate signature
    NSData * jwtSignedData = [[NSString stringWithFormat:@"%@.%@", jwtHeader, jwtClaims] dataUsingEncoding:NSASCIIStringEncoding];
    NSData * jwtSignatureData = [[NSData alloc] initWithJwtEncodedString:jwtSignature];
    XCTAssertNotNil(jwtSignatureData);
    
    result = [_helper.testServerApi verifyDsaSignature:activation.activationId data:jwtSignedData signature:jwtSignatureData signatureFormat:@"JOSE" signatureType:@"ECDSA"];
    XCTAssertTrue(result);
}

#pragma mark - End-2-End Encryption

- (void) testEncryptorCreation
{
    CHECK_TEST_CONFIG();
    
    PowerAuthCoreEncryptor * encryptor = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk encryptorForApplicationScopeWithCallback:^(PowerAuthCoreEncryptor * _Nullable encryptor, NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:encryptor];
        }];
    }];
    XCTAssertNotNil(encryptor);
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    // Re-create SDK to reset internal objects
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:nil biometricConfiguration:nil keychainConfiguration:nil clientConfiguration:nil];
    XCTAssertTrue(_sdk.hasValidActivation);
    
    encryptor = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk encryptorForActivationScopeWithCallback:^(PowerAuthCoreEncryptor * _Nullable encryptor, NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:encryptor];
        }];
    }];
    XCTAssertNotNil(encryptor);
}

#pragma mark - Vault keys

- (PowerAuthSecureVaultKey*) fetchVaultEncryptionKey:(PowerAuthSecureVaultKeyId)keyId
                                         credentials:(PowerAuthAuthentication*)credentials
                                          shouldPass:(BOOL)shouldPass
{
    __block NSError * outError = nil;
    PowerAuthSecureVaultKey * vaultKey = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchSecureVaultKey:credentials keyIdentifier:keyId callback:^(PowerAuthSecureVaultKey * _Nullable encryptionKey, NSError * _Nullable error) {
            outError = error;
            [waiting reportCompletion:encryptionKey];
        }];
    }];
    if (shouldPass) {
        XCTAssertNotNil(vaultKey);
        XCTAssertNil(outError);
        XCTAssertEqual(keyId, vaultKey.keyId);
    } else {
        XCTAssertNil(vaultKey);
        XCTAssertNotNil(outError);
    }
    return vaultKey;
}

- (PowerAuthCoreData*) fetchLegacyVaultKey:(PowerAuthAuthentication*)credentials
                           derivationIndex:(NSUInteger)derivationIndex
                                shouldPass:(BOOL)shouldPass
{
    __block NSError * outError = nil;
    PowerAuthCoreData * vaultKey = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchEncryptionKey:credentials index:derivationIndex callback:^(PowerAuthCoreData * _Nullable encryptionKey, NSError * _Nullable error) {
            outError = error;
            [waiting reportCompletion:encryptionKey];
        }];
    }];
    if (shouldPass) {
        XCTAssertNotNil(vaultKey);
        XCTAssertNil(outError);
    } else {
        XCTAssertNil(vaultKey);
        XCTAssertNotNil(outError);
    }
    return vaultKey;
}

- (void) testVaultEncryptionKeys
{
    // This test requires PAS configured for a very short temporary key lifespan.
    CHECK_TEST_CONFIG();

    PowerAuthSdkActivation * activation = [_helper createActivationWithFlags:TestActivationFlags_PersistWithFakeBiometry activationOtp:nil];
    if (!activation) {
        return;
    }
    NSError * error;
    PowerAuthSecureVaultKey *any2fa, *knowledge, *otherKDK;
    PowerAuthCoreData *legacy, *other, *another;
    if ([_sdk currentAlgorithm] != PowerAuthAlgorithm_LEGACY_P256) {
        // V4
        any2fa = [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_KnowledgeOrBiometry credentials:activation.credentials shouldPass:YES];
        otherKDK = [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_KnowledgeOrBiometry credentials:activation.credentials shouldPass:YES];
        XCTAssertEqualObjects(any2fa, otherKDK);
        otherKDK = [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_KnowledgeOrBiometry credentials:activation.biometryCredentials shouldPass:YES];
        XCTAssertEqualObjects(any2fa, otherKDK);

        knowledge = [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_Knowledge credentials:activation.credentials shouldPass:YES];
        XCTAssertNotEqualObjects(any2fa, knowledge);
        otherKDK = [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_Knowledge credentials:activation.credentials shouldPass:YES];
        XCTAssertEqualObjects(knowledge, otherKDK);
        
        // Derive other keys
        other = [any2fa deriveKeyWithIndex:1000 keySize:32 error:&error];
        XCTAssertNotNil(other);
        XCTAssertEqual(32, other.sensitiveData.length);
        another = [any2fa deriveKeyWithIndex:1000 keySize:32 error:&error];
        XCTAssertEqualObjects(other, another);
        
        other = [knowledge deriveKeyWithIndex:1000 keySize:32 error:&error];
        XCTAssertNotNil(other);
        XCTAssertEqual(32, other.sensitiveData.length);
        another = [knowledge deriveKeyWithIndex:1000 keySize:32 error:&error];
        XCTAssertEqualObjects(other, another);
        
        another = [knowledge deriveKeyWithIndex:1000 keySize:16 error:&error];
        XCTAssertNotEqualObjects(other, another);
        
        // Following fetch operations should fail
        [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_Knowledge credentials:activation.biometryCredentials shouldPass:NO];
        [self fetchLegacyVaultKey:activation.credentials derivationIndex:0 shouldPass:NO];
        [self fetchLegacyVaultKey:activation.biometryCredentials derivationIndex:0 shouldPass:NO];
        
        // Min size is 16
        another = [knowledge deriveKeyWithIndex:1000 keySize:8 error:&error];
        XCTAssertNil(another);
        XCTAssertNotNil(error);

    } else {
        // V3
        legacy = [self fetchLegacyVaultKey:activation.credentials derivationIndex:0 shouldPass:YES];
        XCTAssertNotNil(legacy);
        XCTAssertEqual(16, legacy.sensitiveData.length);
        // Compare to manually created key
        other = [self fetchLegacyVaultKey:activation.credentials derivationIndex:0 shouldPass:YES];
        XCTAssertEqualObjects(legacy, other);
        
        // Following fetch operations should fail
        [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_Knowledge credentials:activation.credentials shouldPass:NO];
        [self fetchVaultEncryptionKey:PowerAuthSecureVaultKeyId_KnowledgeOrBiometry credentials:activation.credentials shouldPass:NO];
        [self fetchLegacyVaultKey:activation.biometryCredentials derivationIndex:0 shouldPass:NO];
    }
}

// TODO: Temporary key expiration

//- (void) testTemporaryKeyExpiration
//{
//    // This test requires PAS configured for a very short temporary key lifespan.
//    CHECK_TEST_CONFIG();
//    
//    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
//    if (!activation) {
//        return;
//    }
//
//    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
//        [_sdk fetchEncryptionKey:_helper.authPossessionWithKnowledge index:1000 callback:^(PowerAuthCoreData * _Nullable encryptionKey, NSError * _Nullable error) {
//            [waiting reportCompletion:@(error == nil)];
//        }];
//    }] boolValue];
//    XCTAssertTrue(result);
//    
//    [NSThread sleepForTimeInterval:15.0];
//    
//    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
//        [_sdk fetchEncryptionKey:_helper.authPossessionWithKnowledge index:1000 callback:^(PowerAuthCoreData * _Nullable encryptionKey, NSError * _Nullable error) {
//            [waiting reportCompletion:@(error == nil)];
//        }];
//    }] boolValue];
//    XCTAssertTrue(result);
//}

#pragma mark - Tokens

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
    PowerAuthHttpHeader * header = [preciousToken generateHeader];
    BOOL result = [_helper validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
    XCTAssertTrue(result);
    
    header = [anotherToken generateHeader];
    result = [_helper validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
    XCTAssertTrue(result);

    // Simulate application's restart
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:_sdk.configuration
                                  biometricConfiguration:_sdk.biometricConfiguration
                                   keychainConfiguration:_sdk.keychainConfiguration
                                     clientConfiguration:_sdk.clientConfiguration];
    tokenStore = _sdk.tokenStore;
    
    // Calculate header with asynchronous method
    header = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id operation = [tokenStore generateAuthenticationHeaderWithName:@"MyPreciousToken" completion:^(PowerAuthHttpHeader * _Nullable header, NSError * _Nullable error) {
            [waiting reportCompletion:header];
        }];
        XCTAssertNotNil(operation);
    }];
    XCTAssertNotNil(header);
    result = [_helper validateTokenHeader:header activationId:activationData.activationId expectedResult:YES];
    
    // Now ask for the same token
    XCTAssertTrue([tokenStore hasLocalTokenWithName:@"MyPreciousToken"]);
    PowerAuthToken * tokenAfterRestart = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [tokenStore requestAccessTokenWithName:@"MyPreciousToken" authentication:possession completion:^(PowerAuthToken * token, NSError * error) {
            [waiting reportCompletion:token];
        }];
    }];
    // And try to generate header
    header = [tokenAfterRestart generateHeader];
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

- (void) createTokenAndValidateTokenHeader:(NSString*)tokenName createToken:(BOOL)createToken
{
    if (createToken) {
        [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            [_sdk.tokenStore requestAccessTokenWithName:tokenName authentication:_helper.authPossession completion:^(PowerAuthToken * _Nullable token, NSError * _Nullable error) {
                XCTAssertNotNil(token);
                [waiting reportCompletion:@(token != nil)];
            }];
        }];
    } else {
        BOOL exists = [_sdk.tokenStore hasLocalTokenWithName:tokenName];
        XCTAssertTrue(exists);
    }
    // Calculate header with asynchronous method
    PowerAuthHttpHeader * header = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id operation = [_sdk.tokenStore generateAuthenticationHeaderWithName:tokenName completion:^(PowerAuthHttpHeader * _Nullable header, NSError * _Nullable error) {
            [waiting reportCompletion:header];
        }];
        XCTAssertNotNil(operation);
    }];
    XCTAssertNotNil(header);
    BOOL validateHeaderResult = [_helper validateTokenHeader:header activationId:_sdk.activationIdentifier expectedResult:YES];
    XCTAssertTrue(validateHeaderResult);
}

#pragma mark - Other tests

- (void) testRestoreSessionState
{
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    NSString * activationFingerprint = [_sdk.activationFingerprint copy];
    NSString * activationIdentifier = [_sdk.activationIdentifier copy];
    XCTAssertEqual(PowerAuthActivationState_Active, [_helper fetchActivationStatus].state);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);


    // Simulate application's restart
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:_sdk.configuration
                                  biometricConfiguration:_sdk.biometricConfiguration
                                   keychainConfiguration:_sdk.keychainConfiguration
                                     clientConfiguration:_sdk.clientConfiguration];
    
    XCTAssertEqualObjects(activationFingerprint, _sdk.activationFingerprint);
    XCTAssertEqualObjects(activationIdentifier, _sdk.activationIdentifier);
    XCTAssertEqual(PowerAuthActivationState_Active, [_helper fetchActivationStatus].state);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);
    
    [_helper cleanup];
}

- (void) testSimulatedHttpResponseFailure
{
    if (![self isRequestFailureSimulatorAvailable]) {
        XCTFail(@"Request failure simulator is not available");
        return;
    }

    // This test validates whether HTTP response failure simulation works properly.

    // Set the next server status failed
    [self simulateNextResponseFailure:@"/status" statusCode:500];
    // Should fail
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchServerStatus:^(PowerAuthServerStatus * _Nullable status, NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertFalse(result);
    // Should work
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchServerStatus:^(PowerAuthServerStatus * _Nullable status, NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertTrue(result);
    // Should fail
    // Set result from any HTTP request as failure
    [self simulateNextResponseFailure:nil statusCode:500];
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchServerStatus:^(PowerAuthServerStatus * _Nullable status, NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertFalse(result);
    // Should work
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchServerStatus:^(PowerAuthServerStatus * _Nullable status, NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertTrue(result);
}

- (void) testFailedStatusFetch
{
    if (![self isRequestFailureSimulatorAvailable]) {
        XCTFail(@"Request failure simulator is not available");
        return;
    }
    // This test validates whether communication between ObjC and C++ request code
    // works properly in case of failure.
    
    XCTAssertFalse(_sdk.hasPendingActivation);
    
    PATSInitActivationResponse * activationData = [_helper.testServerApi initializeActivation:_helper.testServerConfig.userIdentifier
                                                                                otpValidation:PATSActivationOtpValidation_NONE
                                                                                   otp:nil];
    NSString * activationCode = [activationData activationCodeWithoutSignature];
    __block PowerAuthActivationResult * activationResult = nil;
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        // Set next "/pa/*/status" to fail, so time will not be synchronized.
        [self simulateNextResponseFailure:@"/keystore/create" statusCode:500];
        // Create activation
        NSString * activationName = _helper.testServerConfig.userActivationName;
        PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:activationCode name:activationName error:nil];
        [_sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
            activationResult = result;
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertFalse(result);
    XCTAssertFalse(_sdk.hasPendingActivation);
    
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        // Create activation
        NSString * activationName = _helper.testServerConfig.userActivationName;
        PowerAuthActivation * activation = [PowerAuthActivation activationWithActivationCode:activationCode name:activationName error:nil];
        [_sdk createActivation:activation callback:^(PowerAuthActivationResult * result, NSError * error) {
            activationResult = result;
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertTrue(result);
    XCTAssertTrue(_sdk.hasPendingActivation);

    // persist activation
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk persistActivationWithPassword:@"1234" callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertTrue(result);
    
    // commit activation
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    if (status.state == PowerAuthActivationState_PendingCommit) {
        result = [_helper.testServerApi commitActivation:activationData.activationId];
        XCTAssertTrue(result);
    }
    status = [_helper fetchActivationStatus];
    XCTAssertEqual(status.state, PowerAuthActivationState_Active);

    // Activation is now active, let's test the C++ Task failure propagation.
    //
    // This is a bit tricky, we have to calculate too many signatures with no validation on the server,
    // to force a local counter to be too ahead against server's. This will trigger a dummy auth code validation
    // on the server with "possession" factor. We trigger this request to fail. The next similar request should work.
    
    [self simulateNextResponseFailure:@"/auth/validate" statusCode:500];
    [self simulateNextResponseFailure:@"/signature/validate" statusCode:500];

    PowerAuthAuthentication * auth = [PowerAuthAuthentication possessionWithPassword:@"1234"];
    for (int i = 0; i < CTR_LOOKAHEAD + 2; i++) {
        // Just calculate signature on the client. This step simulates a network connection failure.
        PowerAuthHttpHeader * header = [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil error:NULL];
        XCTAssertNotNil(header);
        if ((i % 4) == 0) {
            // Every 4th signature calculation try to get the status
            status = [_helper fetchActivationStatus];
            XCTAssertNotNil(status);
            // Everything should be OK, because getting the status fires signature validation internally.
            XCTAssertEqual(status.state, PowerAuthActivationState_Active);
        }
    }
    // Validate password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk testPassword:@"1234" callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
    }] boolValue];
    XCTAssertTrue(result);
        
    [_helper cleanup];
}

#pragma mark - Tests of protocol upgrade V3 -> V4

- (void) testProtocolUpgrade
{
    CHECK_TEST_CONFIG();
    
    //
    // Test successful upgrade from V3 to V4 protocol.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:0];
    
    [self createTokenAndValidateTokenHeader:@"TestToken" createToken:YES];
        
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    
    if (self.powerAuthAlgorithm > PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertFalse(result.activationStatusFetchRequired);
        XCTAssertNotNil(result.activationFingerprint);
    }
    
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    
    [self createTokenAndValidateTokenHeader:@"TestToken" createToken:NO];
        
    [_helper cleanup];
}

- (void) testProtocolUpgradeWithBiometry
{
    CHECK_TEST_CONFIG();
    
    //
    // Test successful upgrade from V3 to V4 protocol.
    // In this case the activation has also biometry
    // factor enabled and so the test also covers
    // the upgrade to longer biometry KEK.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:TestActivationFlags_PersistWithFakeBiometry];
    XCTAssertTrue(_sdk.hasBiometryFactor);

    // Start protocol upgrade with custom new biometry KEK.
    PowerAuthCoreData * newBiometryKek = [PowerAuthCoreCryptoUtils randomCoreData:32];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:newBiometryKek shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    XCTAssertTrue(_sdk.hasBiometryFactor);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    PowerAuthAuthentication * biometryAuth;
    if (self.powerAuthAlgorithm > PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertFalse(result.activationStatusFetchRequired);
        XCTAssertNotNil(result.activationFingerprint);
        biometryAuth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:newBiometryKek customPossessionKey:nil];
    } else {
        biometryAuth = _helper.currentActivation.biometryCredentials;
    }
    
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    BOOL authenticationValid = [_helper validateAuthentication:biometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertTrue(authenticationValid);
    
    [_helper cleanup];
}

- (void) testProtocolUpgrade_fetchStatusFailure
{
    CHECK_TEST_CONFIG();
    
    //
    // Test unsuccessful upgrade from V3 to V4 protocol. In this case
    // there is a simulated network error when fetching the activation
    // status. Meaning the upgrade procedure cannot actually start.
    // Upgrade task should fail, the system state must remain unchanged.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:TestActivationFlags_PersistWithFakeBiometry];
    
    // Activation status fetch fails for this test.
    [self simulateNetworkErrorOnSend:@"/pa/v3/activation/status"];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:NO];
    
    // Assert protocol version did not change.
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertNil(result);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);

    // Activation status is still active and upgrade is available.
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertEqual(_sdk.hasProtocolUpgradeAvailable, targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256);
    
    // Assert the old biometry factor key still works.
    PowerAuthAuthentication * oldBiometryAuth = _helper.currentActivation.biometryCredentials;
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    BOOL authenticationValid = [_helper validateAuthentication:oldBiometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertTrue(authenticationValid);
    
    [_helper cleanup];
}

- (void) testProtocolUpgrade_upgradeStartResponseFailure
{
    CHECK_TEST_CONFIG();
    
    //
    // Test unsuccessful upgrade from V3 to V4 protocol. In this case
    // there is a simulated response failure when starting the upgrade.
    // Upgrade task should fail, the system state must remain unchanged.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:TestActivationFlags_PersistWithFakeBiometry];
    
    [self simulateNextResponseFailure:@"/pa/v4/upgrade/start" statusCode:500];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:NO];
    
    // Protocol version did not change.
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertNil(result);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);

    // Activation status is still active and upgrade is available.
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertEqual(_sdk.hasProtocolUpgradeAvailable, targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256);
    
    // Assert the old biometry factor key still works.
    PowerAuthAuthentication * oldBiometryAuth = _helper.currentActivation.biometryCredentials;
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    BOOL authenticationValid = [_helper validateAuthentication:oldBiometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertTrue(authenticationValid);

    if (self.powerAuthAlgorithm != PowerAuthAlgorithm_LEGACY_P256) {
        // try-again
        result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:YES];
        XCTAssertNotNil(result);
    }
        
    [_helper cleanup];
}

- (void) testProtocolUpgrade_upgradeConfirmResponseFailure
{
    CHECK_TEST_CONFIG();
    
    //
    // Test successful upgrade from V3 to V4 protocol. In this case
    // there is a simulated response failure when confirming the upgrade.
    // Even though the upgrade confirm response was not received, server
    // has processed the confirm request, and so the following activation
    // status shows the upgrade is completed.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:TestActivationFlags_PersistWithFakeBiometry];
    
    // Simulate response failure of the upgrade confirm.
    [self simulateNextResponseFailure:@"/pa/v4/upgrade/confirm" statusCode:500];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    if (self.powerAuthAlgorithm <= PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertNil(result);
        XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
        return;
    }
    
    // Protocol version upgraded locally.
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    // Upgrade is not confirmed, still in progress.
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    
    // Result of the protocol upgrade shows that activation status should be fetched.
    XCTAssertTrue(result.activationStatusFetchRequired);
    XCTAssertNil(result.activationFingerprint);
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];

    // The activation status shows upgrade is completed.
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    // Check that the old biometry factor does not work anymore.
    PowerAuthAuthentication * oldBiometryAuth = _helper.currentActivation.biometryCredentials;
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    BOOL authenticationValid = [_helper validateAuthentication:oldBiometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertFalse(authenticationValid);

    [_helper cleanup];
}

- (void) testProtocolUpgrade_upgradeConfirmRequestFailure
{
    CHECK_TEST_CONFIG();
    CHECK_BIOMETRY();
    
    //
    // Test successful upgrade from V3 to V4 protocol. In this case
    // there is a simulated network error 3 times in the row when
    // sending the upgrade confirm request. Meaning that the task
    // completes while the server still awaits the upgrade confirm.
    // To finish the protocol upgrade, activation status fetch is
    // required to confirm the protocol upgrade in the background.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    PowerAuthCoreData * newBiometryKek = [PowerAuthCoreCryptoUtils randomCoreData:32];
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:TestActivationFlags_PersistWithBiometry];
    
    // Set 3 failures in a row, as there are 3 confirm attempts in the task.
    [self simulateNetworkErrorOnSend:@"/pa/v4/upgrade/confirm" repeatCount:3];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:newBiometryKek shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    if (self.powerAuthAlgorithm <= PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertNil(result);
        XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
        return;
    }
    
    // Protocol version is upgraded.
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    
    // Simulate application restart before testing authentication.
    _sdk = [_helper reCreateSdkInstance];
    
    // Check biometry factor not possible during upgrade.
    PowerAuthAuthentication * newBiometryAuth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:newBiometryKek customPossessionKey:nil];
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    
    // Authentication header calculation not allowed when protocol upgrade pending.
    NSError * authCalcError;
    [_sdk authenticationHeaderForRequestWithBodyWithAuthentication:newBiometryAuth method:@"POST" uriId:@"/hello/there" body:randomData error:&authCalcError];
    XCTAssertEqual(PowerAuthErrorCode_PendingProtocolUpgrade, authCalcError.powerAuthErrorCode);
    // Same applies to offline.
    [_sdk offlineAuthenticationCodeWithAuthentication:newBiometryAuth uriId:@"/hello/there" body:randomData nonce:@"trustmeitisarandomstring" callback:^(NSString * authenticationCode, NSError * error){
        XCTAssertEqual(PowerAuthErrorCode_PendingProtocolUpgrade, error.powerAuthErrorCode);
    }];
    
    BOOL authenticationValid = [_helper validateAuthentication:newBiometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertFalse(authenticationValid);
    
    // Result of the protocol upgrade shows that activation status should be fetched.
    XCTAssertTrue(result.activationStatusFetchRequired);
    XCTAssertNil(result.activationFingerprint);
    
    // Make the background confirm request fail too.
    [self simulateNetworkErrorOnSend:@"/pa/v4/upgrade/confirm"];
    NSError * error = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status,NSError * error) {
            [waiting reportCompletion:error];
        }];
    }];
    // Fetch failed, because the background confirm failed.
    XCTAssertNotNil(error);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    
    // Simulate application restart before testing authentication.
    _sdk = [_helper reCreateSdkInstance];
    authenticationValid = [_helper validateAuthentication:newBiometryAuth
                                                     data:randomData
                                                   method:@"POST"
                                                    uriId:@"/hello/there"
                                                   online:YES
                                                  cripple:0];
    XCTAssertTrue(authenticationValid);
    

    [_helper cleanup];
}

- (void) testProtocolUpgrade_upgradeConfirmRequestAndStatusResponseFailure
{
    CHECK_TEST_CONFIG();
    
    //
    // Test successful upgrade from V3 to V4 protocol. In this case
    // there is a simulated network error when sending the upgrade
    // confirm request followed by activation status response failure.
    // Meaning that the task completes without multiple attempts, while
    // the server still awaits the upgrade confirm. To finish the
    // protocol upgrade, activation status fetch is required to confirm
    // the protocol upgrade in the background.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:0];
    
    // Fail the upgrade confirm, and the following status to fail without trying more attempts.
    [self simulateNetworkErrorOnSend:@"/pa/v4/upgrade/confirm"];
    [self simulateNextResponseFailure:@"/pa/v4/activation/status" statusCode:500];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    if (self.powerAuthAlgorithm <= PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertNil(result);
        XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
        return;
    }
    
    // Protocol version is upgraded.
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    
    // Result of the protocol upgrade shows that activation status should be fetched.
    XCTAssertTrue(result.activationStatusFetchRequired);
    XCTAssertNil(result.activationFingerprint);
    PowerAuthActivationStatus * status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    [_helper cleanup];
}

- (void) testProtocolUpgrade_newBiometryKekWithoutBiometryFactorSet
{
    CHECK_TEST_CONFIG();
    
    //
    // Test successful upgrade from V3 to V4 protocol. In this case
    // a new biometry KEK is passed to the protocol upgrade task,
    // even though the biometry factor is not set for the V3.
    //
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:0];
    
    PowerAuthCoreData * newBiometryKek = [PowerAuthCoreCryptoUtils randomCoreData:32];
    PowerAuthProtocolUpgradeResult * result = [_helper startProtocolUpgradeWithCustomBiometryKek:newBiometryKek shouldFinish:targetAlgorithm > PowerAuthAlgorithm_LEGACY_P256];
    
    if (self.powerAuthAlgorithm <= PowerAuthAlgorithm_LEGACY_P256) {
        XCTAssertNil(result);
        XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
        return;
    }
    
    // Protocol version is upgraded.
    XCTAssertEqual(targetAlgorithm, _sdk.currentAlgorithm);
    XCTAssertFalse(result.activationStatusFetchRequired);
    XCTAssertNotNil(result.activationFingerprint);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    // Check biometry factor not set.
    XCTAssertFalse(_sdk.hasBiometryFactor);
    PowerAuthAuthentication * newBiometryAuth = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:newBiometryKek customPossessionKey:nil];
    NSData * randomData = [[[PowerAuthCoreCryptoUtils randomBytes:42] base64EncodedStringWithOptions:0] dataUsingEncoding:NSASCIIStringEncoding];
    BOOL authenticationValid = [_helper validateAuthentication:newBiometryAuth
                                                          data:randomData
                                                        method:@"POST"
                                                         uriId:@"/hello/there"
                                                        online:YES
                                                       cripple:0];
    XCTAssertFalse(authenticationValid);
    
    [_helper cleanup];
}

- (void) testProtocolUpgrade_withRestarts
{
    CHECK_TEST_CONFIG();
    
    //
    // Test upgrade from V3 to V4 protocol. In this case
    // there are simulated errors and restarts of the application.
    //
    if (self.powerAuthAlgorithm <= PowerAuthAlgorithm_LEGACY_P256) {
        PowerAuthLog(@"Test case '%@' is irrelevant for PowerAuthAlgorithm_LEGACY_P256", self);
        return;
    }
    
    const PowerAuthAlgorithm targetAlgorithm = self.powerAuthAlgorithm;
    _sdk = [_helper prepareActivationForUpgradeTest:targetAlgorithm withFlags:0];
    
    PowerAuthProtocolUpgradeResult * result;
    PowerAuthActivationStatus * status;
    
    /// The upgrade start request fails, keeping the application state as it was
    /// before the upgrade attempt. Even after restart of the application.
    [self simulateNetworkErrorOnSend:@"/pa/v4/upgrade/start"];
    result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:NO];
    XCTAssertNil(result);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertTrue(_sdk.hasProtocolUpgradeAvailable);
    _sdk = [_helper reCreateSdkInstance];
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertTrue(_sdk.hasProtocolUpgradeAvailable);
    
    /// The upgrade start response fails, keeping the application state as it was
    /// before the upgrade attempt. Even after restart of the application.
    [self simulateNextResponseFailure:@"/pa/v4/upgrade/start" statusCode:500];
    result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:NO];
    XCTAssertNil(result);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertTrue(_sdk.hasProtocolUpgradeAvailable);
    _sdk = [_helper reCreateSdkInstance];
    XCTAssertEqual(PowerAuthAlgorithm_LEGACY_P256, _sdk.currentAlgorithm);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertTrue(_sdk.hasProtocolUpgradeAvailable);

    /// The upgrade has started, but confirm request fails and status cannot be fetched.
    /// SDK protocol was upgraded locally, but the confirm is still pending. The pending
    /// upgrade state should be preserved despite application restart.
    [self simulateNetworkErrorOnSend:@"/pa/v4/upgrade/confirm"];
    [self simulateNextResponseFailure:@"/pa/v4/activation/status" statusCode:500];
    result = [_helper startProtocolUpgradeWithCustomBiometryKek:nil shouldFinish:YES];
    XCTAssertNotNil(result);
    XCTAssertTrue(result.activationStatusFetchRequired);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    _sdk = [_helper reCreateSdkInstance];
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    
    /// After application restart, the status could not be fetched, meaning the upgrade
    /// confirm cannot be requested. After another application restart, the protocol
    /// upgrade process is still pending.
    [self simulateNextResponseFailure:@"/pa/v4/activation/status" statusCode:500];
    NSError * error = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status,NSError * error) {
            [waiting reportCompletion:error];
        }];
    }];
    XCTAssertNotNil(error);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    _sdk = [_helper reCreateSdkInstance];
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
    XCTAssertTrue(_sdk.hasPendingProtocolUpgrade);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    
    /// Activation status fetch is now success. After application restart
    /// the protocol upgrade should be already confirmed.
    [_helper fetchActivationStatus];
    _sdk = [_helper reCreateSdkInstance];
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    /// Final activation status fetch shows the protocol upgrade is completed.
    status = [_helper fetchActivationStatus];
    XCTAssertTrue(status.state == PowerAuthActivationState_Active);
    XCTAssertEqual(self.powerAuthAlgorithm, _sdk.currentAlgorithm);
    XCTAssertFalse(_sdk.hasProtocolUpgradeAvailable);
    XCTAssertFalse(_sdk.hasPendingProtocolUpgrade);
    
    [_helper cleanup];
}

@end
