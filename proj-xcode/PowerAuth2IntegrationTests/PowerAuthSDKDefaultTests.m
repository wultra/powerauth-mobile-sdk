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

#import "PowerAuthSDKDefaultTests.h"
#import "PA2ObjectSerialization.h"

@implementation PowerAuthSDKDefaultTests

#pragma mark - Test setup

- (void)setUp
{
    [super setUp];
    [self reconfigureForTest:nil];
}

- (void) tearDown
{
    [_helper cleanup];
    [super tearDown];
}


- (void) prepareConfigs:(PowerAuthConfiguration**)configuration
         keychainConfig:(PowerAuthKeychainConfiguration**)keychainConfiguration
           clientConfig:(PowerAuthClientConfiguration**)clientConfiguration
            forTestName:(NSString*)testName
{
    if ([testName isEqualToString:@"testCustomOfflineSignature"]) {
        (*configuration).offlineSignatureComponentLength = 4;
    }
}

- (void) reconfigureForTest:(NSString *)testName
{
    _helper = [PowerAuthSdkTestHelper createCustom:^(PowerAuthConfiguration **configuration, PowerAuthKeychainConfiguration **keychainConfiguration, PowerAuthClientConfiguration **clientConfiguration) {
        [self prepareConfigs:configuration keychainConfig:keychainConfiguration clientConfig:clientConfiguration forTestName:testName];
    }];
    [_helper printConfig];
    _sdk = _helper.sdk;
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
  Checks whether biometry is available for testing.
 */
#define CHECK_BIOMETRY()        \
    if (![PowerAuthKeychain canUseBiometricAuthentication]) { \
        XCTFail(@"Biometric authentication is not available on this simulator. Please go to Device Simulator and make sure that `Features -> Face/Touch ID -> Enrolled` is ON"); \
        return;                 \
    }


#pragma mark - Integration tests

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


- (void) testCreateActivationWithhoutSignature
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
    result = [_helper checkForPassword:@"MustBeWring"];
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
    
    // 1) At first, change password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk changeCorePasswordFrom:auth.password to:newPassword callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now validate that new password
    result = [_helper checkForCorePassword:newPassword];
    XCTAssertTrue(result);
    
    // Now use string version instead of core password
    
    NSString * oldStringPassword = newPassword.extractedPassword;
    NSString * newStringPassword = auth.password.extractedPassword;
    // 1) At first, change password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk changePasswordFrom:oldStringPassword to:newStringPassword callback:^(NSError * _Nullable error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        // Returned task should not be cancelled
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertTrue(result);
    
    // 2) Now validate that new password
    result = [_helper checkForPassword:newStringPassword];
    XCTAssertTrue(result);
}



- (void) testValidateSignature
{
    CHECK_TEST_CONFIG();
    
    //
    // This test validates functions for PA signature calculations.
    //
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PowerAuthAuthentication * auth_possession = _helper.authPossession;
    PowerAuthAuthentication * auth_possession_knowledge = _helper.authPossessionWithKnowledge;
    
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
            result = [_helper validateSignature:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0];
            XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        }
        result = [_helper validateSignature:auth_possession_knowledge data:data method:online_mode ? @"GET" : @"POST" uriId:@"/hello/hacker" online:online_mode cripple:0];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        // Negative
        result = [_helper validateSignature:auth_possession data:data method:@"POST" uriId:@"/hello/world" online:online_mode cripple:0x0001];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateSignature:auth_possession_knowledge data:data method:@"GET" uriId:@"/hello/hacker" online:online_mode cripple:0x0010];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateSignature:auth_possession data:data method:@"GET" uriId:@"/hello/from/test" online:online_mode cripple:0x0100];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
        result = [_helper validateSignature:auth_possession_knowledge data:data method:@"POST" uriId:@"/hello/from/test" online:online_mode cripple:0x1000];
        XCTAssertTrue(result, @"Failed for %@ mode", online_mode ? @"online" : @"offline");
    }
    
    // Do more valid signatures. Count is important, due to fact that we have 8-bit local counter sice V3.1
    for (int i = 1; i < 264; i++) {
        result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
            id<PowerAuthOperationTask> task = [_sdk validateCorePassword:auth.password callback:^(NSError * error) {
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

- (void) testCustomOfflineSignature
{
    [self reconfigureForTest:@"testCustomOfflineSignature"];
    
    CHECK_TEST_CONFIG();
    
    //
    // This test validates offline signatures with custom length.
    //
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    
    NSString * nonce = @"QVZlcnlDbGV2ZXJOb25jZQ==";
    NSError * error = nil;
    NSString * signature = [_sdk offlineSignatureWithAuthentication:[PowerAuthAuthentication possession] uriId:@"/some/uriId" body:nil nonce:nonce error:&error];
    XCTAssertNotNil(signature);
    XCTAssertEqual(4, signature.length);
}

- (void) testVerifyServerSignedData
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks whether SDK can verify data signed by server's master key
    //
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
    PATSOfflineSignaturePayload * payload;
    {
        // Verify data signed with master key (non-personalized)
        NSString * dataForSigning = @"All your money are belong to us!";
        payload = [_helper.testServerApi createNonPersonalizedOfflineSignaturePayload:activation.activationData.applicationId data:dataForSigning];
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
        payload = [_helper.testServerApi createPersonalizedOfflineSignaturePayload:activation.activationId data:dataForSigning];
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

    PowerAuthAuthentication * sign_auth = [auth copy];
    NSString * local_signature = [_sdk offlineSignatureWithAuthentication:sign_auth uriId:uriId body:body nonce:nonce error:NULL];
    XCTAssertNotNil(local_signature);

    NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:uriId nonce:nonce data:body];
    XCTAssertNotNil(normalized_data);
    PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineSignature:activation.activationData.activationId data:normalized_data signature:local_signature allowBiometry:NO];
    XCTAssertTrue(response.signatureValid);
}

- (void) testSignDataWithDevicePrivateKey
{
    CHECK_TEST_CONFIG();
    
    //
    // This test checks data signing with device's private key.
    //
    
    BOOL result;
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    
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
        result = [_helper.testServerApi verifyECDSASignature:activation.activationId data:dataForSigning signature:resultSignature];
        XCTAssertTrue(result);
    }
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
    PATSVerifySignatureResponse * response = [_helper.testServerApi verifySignature:activation.activationId data:normalized_data signature:sig_nonce[0] signatureType:@"POSSESSION" signatureVersion:_helper.paVer];
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
        PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil  error:NULL];
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
        PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:auth method:@"POST" uriId:@"/some/identifier" body:nil  error:NULL];
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
        NSString * local_signature = [_sdk offlineSignatureWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" error:NULL];
        NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
        PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineSignature:_sdk.activationIdentifier data:normalized_data signature:local_signature allowBiometry:NO];
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
        NSString * local_signature = [_sdk offlineSignatureWithAuthentication:auth uriId:@"/test/id" body:data_to_sign nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" error:NULL];
        NSString * normalized_data = [_helper.testServerApi normalizeDataForSignatureWithMethod:@"POST" uriId:@"/test/id" nonce:@"QVZlcnlDbGV2ZXJOb25jZQ==" data:data_to_sign];
        PATSVerifySignatureResponse * response = [_helper.testServerApi verifyOfflineSignature:_sdk.activationIdentifier data:normalized_data signature:local_signature allowBiometry:NO];
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
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthAuthentication * auth = activation.credentials;
    PATSInitActivationResponse * activationData = activation.activationData;
    PowerAuthActivationResult * activationResult = activation.activationResult;
    PowerAuthActivationRecoveryData * recoveryData = activationResult.activationRecovery;
    
    if (!recoveryData) {
        NSLog(@"WARNING: Server doesn't support recovery codes.");
        XCTAssertFalse([_sdk hasActivationRecoveryData]);
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
        NSString * activationName = _helper.testServerConfig.userActivationName;
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
    
    PATSActivationStatus * serverOldActivationStatus = [_helper.testServerApi getActivationStatus:activationData.activationId challenge:nil];
    XCTAssertNotNil(serverOldActivationStatus);
    XCTAssertTrue([serverOldActivationStatus.activationStatus isEqualToString:@"REMOVED"]);

    
    // 6. Create a new authentication and persist it in the SDK.
    
    auth = [_helper createAuthentication];
    result = [_sdk persistActivationWithAuthentication:auth error:&operationError];
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
        id<PowerAuthOperationTask> task = [_sdk validatePassword:@"MustBeWrong" callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    XCTAssertFalse(result); // Must not pass. Activation is blocked
    
    // 3) Now use a valid password
    result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk validateCorePassword:auth.password callback:^(NSError * error) {
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
        id<PowerAuthOperationTask> task = [_sdk validateCorePassword:auth.password callback:^(NSError * error) {
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
    
    NSError * err = nil;
    BOOL res = [_sdk persistActivationWithPassword:@"1234" error:&err];
    XCTAssertFalse(res);
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
    
    NSData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    
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
    
    NSData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    PowerAuthConfiguration * newConfig = [_sdk.configuration copy];
    newConfig.externalEncryptionKey = eek;
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:newConfig keychainConfiguration:nil clientConfiguration:nil];
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
    NSData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
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
    
    NSData * eek = [PowerAuthCoreSession generateSignatureUnlockKey];
    
    NSError * error = nil;
    BOOL result = [_sdk addExternalEncryptionKey:eek error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);
    
    XCTAssertTrue(_sdk.hasExternalEncryptionKey);
    XCTAssertTrue([_helper checkForCorePassword:activation.credentials.password]);

    // Now re-instantiate SDK and try to set EEK manually
    PowerAuthConfiguration * newConfig = [_sdk.configuration copy];
    newConfig.externalEncryptionKey = nil;
    _sdk = [_helper reCreateSdkInstanceWithConfiguration:newConfig keychainConfiguration:nil clientConfiguration:nil];
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
        [_sdk validateCorePassword:activation.credentials.password callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
        id<PowerAuthOperationTask> task = [_sdk validateCorePassword:activation.credentials.password callback:^(NSError * _Nullable error) {
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
    PowerAuthAuthorizationHttpHeader * header;
    
    NSError * error = nil;
    authentication = [PowerAuthAuthentication possessionWithBiometry];
    header = [_sdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
    XCTAssertNil(header);
    if (supportsBiometry) {
        XCTAssertEqual(PowerAuthErrorCode_BiometryFailed, error.powerAuthErrorCode);
    } else {
        XCTAssertEqual(PowerAuthErrorCode_BiometryNotAvailable, error.powerAuthErrorCode);
    }
    
    error = nil;
    authentication = [PowerAuthAuthentication possessionWithBiometryPrompt:@"Authenticate with biometry"];
    header = [_sdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
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
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk addBiometryFactorWithCorePassword:activation.credentials.password callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertTrue([_sdk hasBiometryFactor]);
    
    XCTAssertTrue([_sdk removeBiometryFactor]);
    
    XCTAssertFalse([_sdk hasBiometryFactor]);
    
    [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk addBiometryFactorWithPassword:activation.credentials.password.extractedPassword callback:^(NSError * _Nullable error) {
            XCTAssertNil(error);
            [waiting reportCompletion:nil];
        }];
    }];
    
    XCTAssertTrue([_sdk hasBiometryFactor]);
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
    PowerAuthAuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/some/uri/id" body:[NSData data] error:&error];
    XCTAssertNil(header);
    XCTAssertEqual(PowerAuthErrorCode_BiometryFailed, error.powerAuthErrorCode);
}

#endif // PA2_BIOMETRY_SUPPORT

#pragma mark - JWT

- (void) testUserInfo
{
    CHECK_TEST_CONFIG();
    
    PowerAuthSdkActivation * activation = [_helper createActivation:YES];
    if (!activation) {
        return;
    }
    PowerAuthUserInfo * infoFromActivation = activation.activationResult.userInfo;
    NSString * userId = _helper.testServerConfig.userIdentifier;
    XCTAssertNotNil(_sdk.lastFetchedUserInfo);
    XCTAssertNotNil(infoFromActivation);
    XCTAssertEqualObjects(userId, _sdk.lastFetchedUserInfo.subject);
    XCTAssertEqualObjects(userId, infoFromActivation.subject);
    
    PowerAuthUserInfo * info = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [_sdk fetchUserInfo:^(PowerAuthUserInfo * userInfo, NSError * error) {
            XCTAssertNil(error);
            [waiting reportCompletion:userInfo];
        }];
    }];
    XCTAssertNotNil(info);
    XCTAssertEqualObjects(info.subject, _helper.testServerConfig.userIdentifier);
    XCTAssertEqual(info, _sdk.lastFetchedUserInfo);
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
        [_sdk signJwtWithDevicePrivateKey:_helper.authPossessionWithKnowledge claims:originalClaims callback:^(NSString * jwt, NSError * error) {
            [waiting reportCompletion:jwt];
        }];
    }];
    
    // Parse JWT and validate result
    XCTAssertNotNil(jwt);
    NSArray * jwtComponents = [jwt componentsSeparatedByString:@"."];
    XCTAssertEqual(3, jwtComponents.count);
    if (jwtComponents.count != 3) {
        return;
    }
    NSString * jwtHeader = jwtComponents[0];
    NSString * jwtClaims = jwtComponents[1];
    NSString * jwtSignature = jwtComponents[2];
    // Validate header
    NSData * jwtHeaderData = [[NSData alloc] initWithJwtEncodedString:jwtHeader];
    XCTAssertNotNil(jwtHeaderData);
    NSDictionary * headerObject = [NSJSONSerialization JSONObjectWithData:jwtHeaderData options:0 error:NULL];
    XCTAssertNotNil(headerObject);
    XCTAssertEqualObjects(@"JWT", headerObject[@"typ"]);
    XCTAssertEqualObjects(@"ES256", headerObject[@"alg"]);
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
    BOOL result = [_helper.testServerApi verifyECDSASignature:_sdk.activationIdentifier
                                                         data:jwtSignedData
                                                    signature:jwtSignatureData
                                              signatureFormat:@"JOSE"];
    XCTAssertTrue(result);
}

@end
