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

#import "PowerAuthSdkTestHelper.h"

@implementation PowerAuthSdkActivation

- (id) initWithActivationData:(PATSInitActivationResponse*)activationData
                  credentials:(PowerAuthAuthentication*)credentials
             activationResult:(PowerAuthActivationResult*)activationResult
{
    self = [super init];
    if (self) {
        _activationData = activationData;
        _credentials = [credentials copyForSigning];
        _activationResult = activationResult;
    }
    return self;
}

- (BOOL) success
{
    return _activationResult != nil;
}

- (void) setAlreadyRemoved
{
    _alreadyRemoved = YES;
}

- (NSString*) activationId
{
    return _activationData.activationId;
}
@end


static NSString * PA_Ver = @"3.1";

@implementation PowerAuthSdkTestHelper

#pragma mark - Init + Config

- (id) initWithSdk:(PowerAuthSDK*)sdk
     testServerApi:(PowerAuthTestServerAPI*)testServerApi
  testServerConfig:(PowerAuthTestServerConfig*)testServerConfig
{
    self = [super init];
    if (self) {
        _sdk = sdk;
        _testServerApi = testServerApi;
        _testServerConfig = testServerConfig;
    }
    return self;
}

- (void) printConfig
{
    NSLog(@"=======================================================================");
    NSLog(@"The integration tests will run against following servers:");
    NSLog(@"    REST API Server: %@", _testServerConfig.enrollmentUrl);
    NSLog(@"    SOAP API Server: %@", _testServerConfig.serverApiUrl);
    NSLog(@"               User: %@", _testServerConfig.userIdentifier);
    NSLog(@"=======================================================================");
}

+ (void) setupLog
{
    if (!PowerAuthLogIsEnabled()) {
        PowerAuthLogSetEnabled(YES);
        PowerAuthLogSetVerbose(NO);
    }
}

+ (PowerAuthTestServerConfig*) loadConfiguration
{
    PowerAuthTestServerConfig * config = nil;
    NSBundle * bundle = [NSBundle bundleForClass:[self class]];
    NSString * path = [bundle pathForResource:@"TestConfig/Configuration" ofType:@"json"];
    if (path) {
        config = [PowerAuthTestServerConfig loadFromJsonFile:path];
        if (config == nil) {
            return nil;
        }
    } else {
        config = [PowerAuthTestServerConfig defaultConfig];
    }
    return config;
}

+ (PowerAuthSdkTestHelper*) createDefault
{
    return [self createCustom:nil];
}

+ (PowerAuthSdkTestHelper*) createCustom:(void (^)(PowerAuthConfiguration * configuration, PowerAuthKeychainConfiguration * keychainConfiguration, PowerAuthClientConfiguration * clientConfiguration))configurator
{
    [self setupLog];
    
    PowerAuthTestServerConfig * testConfig = [self loadConfiguration];
    if (!testConfig) {
        return nil;
    }
    PowerAuthTestServerAPI * testServerApi = [[PowerAuthTestServerAPI alloc] initWithConfiguration:testConfig];
    BOOL result = [testServerApi validateConnection];
    XCTAssertTrue(result, @"Connection to test server failed. Check debug log for details.");
    if (!result) {
        return nil;
    }
    PowerAuthConfiguration *config = [[PowerAuthConfiguration alloc] init];
    config.instanceId = @"IntegrationTests";
    config.baseEndpointUrl = testConfig.enrollmentUrl;
    config.appKey = testServerApi.appVersion.applicationKey;
    config.appSecret = testServerApi.appVersion.applicationSecret;
    config.masterServerPublicKey = testServerApi.appDetail.masterPublicKey;
    PowerAuthKeychainConfiguration * keychainConfig = [[PowerAuthKeychainConfiguration sharedInstance] copy];
    PowerAuthClientConfiguration * clientConfig = [[PowerAuthClientConfiguration sharedInstance] copy];
    if (configurator) {
        configurator(config, keychainConfig, clientConfig);
    }
    result = [config validateConfiguration];
    XCTAssertTrue(result, @"Constructed configuration is not valid.");
    if (!result) {
        return nil;
    }
    
    PowerAuthSDK *sdk = [[PowerAuthSDK alloc] initWithConfiguration:config
                                              keychainConfiguration:keychainConfig
                                                clientConfiguration:clientConfig];
    [sdk removeActivationLocal];
    
    result = sdk != nil;
    result = result && [sdk hasPendingActivation] == NO;
    
    XCTAssertTrue(result, @"PowerAuthSDK ended in unexpected state.");
    if (!result) {
        return nil;
    }
    return [[PowerAuthSdkTestHelper alloc] initWithSdk:sdk
                                         testServerApi:testServerApi
                                      testServerConfig:testConfig];
}

+ (PowerAuthSdkTestHelper*) clone:(PowerAuthSdkTestHelper*)testHelper
                withConfiguration:(PowerAuthConfiguration*)configuration
{
    [self setupLog];
    
    PowerAuthSDK *sdk = [[PowerAuthSDK alloc] initWithConfiguration:configuration];
    [sdk removeActivationLocal];
    
    BOOL result = sdk != nil;
    result = result && [sdk hasPendingActivation] == NO;
    
    XCTAssertTrue(result, @"Cloned PowerAuthSDK ended in unexpected state.");
    if (!result) {
        return nil;
    }
    return [[PowerAuthSdkTestHelper alloc] initWithSdk:sdk
                                         testServerApi:testHelper.testServerApi
                                      testServerConfig:testHelper.testServerConfig];
}

- (NSString*) paVer
{
    return PA_Ver;
}

#pragma mark - Core

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

#pragma mark - Activation

- (PowerAuthAuthentication*) authPossession
{
    if (_currentActivation) {
        return [PowerAuthAuthentication possession];
    }
    return nil;
}

- (PowerAuthAuthentication*) authPossessionWithKnowledge
{
    return [_currentActivation.credentials copy];
}

- (PowerAuthAuthentication*) badAuthPossessionWithKnowledge
{
    return [PowerAuthAuthentication possessionWithPassword:@"alwaysBadPassword"];
}

- (PATSInitActivationResponse*) prepareActivation:(BOOL)useSignature
                                    activationOtp:(NSString*)activationOtp
{
    PATSActivationOtpValidationEnum otpValidation = activationOtp != nil ? PATSActivationOtpValidation_ON_KEY_EXCHANGE : PATSActivationOtpValidation_NONE;
    return [_testServerApi initializeActivation:_testServerConfig.userIdentifier
                                  otpValidation:otpValidation
                                            otp:activationOtp];
}

- (PowerAuthSdkActivation*) createActivationWithFlags:(TestActivationFlags)flags activationOtp:(NSString *)activationOtp
{
    BOOL useSignature = (flags & TestActivationFlags_UseSignature) != 0;
    BOOL removeAfter = (flags & TestActivationFlags_RemoveAfter) != 0;
    BOOL commitWithPass = (flags & TestActivationFlags_CommitWithPlainPassword) != 0;
    BOOL commitWithCorePass = (flags & TestActivationFlags_CommitWithCorePassword) != 0;
    BOOL commitWithBio  = (flags & TestActivationFlags_CommitWithBiometry) != 0;
    _currentActivation = nil;
    
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
    if (!result) {
        return nil;
    }
    
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
    PowerAuthAuthentication * auth = commitWithBio ? [self createAuthenticationWithBiometry] : [self createAuthentication];
    if (commitWithPass) {
        result = [_sdk commitActivationWithPassword:auth.password.extractedPassword error:&error];
    } else if (commitWithCorePass) {
        result = [_sdk commitActivationWithCorePassword:auth.password error:&error];
    } else {
        // By default, use authentication for commit
        result = [_sdk commitActivationWithAuthentication:auth error:&error];
    }
    if (!result) {
        return nil;
    }
    
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
        if (_testServerConfig.isServerAutoCommit) {
            XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
        } else {
            XCTAssertTrue(activationStatus.state == PowerAuthActivationState_PendingCommit);
        }
        if (!_testServerConfig.isServerAutoCommit) {
            // 4) SERVER: This is the last step of activation. We need to commit an activation on the server side.
            //            This is typically done internally on the server side and depends on activation flow
            //            in concrete internet banking project.
            result = [_testServerApi commitActivation:activationData.activationId];
            XCTAssertTrue(result, @"Server's commit failed");
            if (!result) {
                return nil;
            }
            // 5) CLIENT: Fetch status again. Now the state should be active
            activationStatus = [self fetchActivationStatus];
            XCTAssertNotNil(activationStatus);
            XCTAssertTrue(activationStatus.state == PowerAuthActivationState_Active);
        }
    }
    
    // Post activation steps...
    result = [_sdk.activationIdentifier isEqualToString:activationData.activationId];
    XCTAssertTrue(result, @"Activation identifier in session is different to identifier generated on the server.");
    if (!result) {
        return nil;
    }
    
    // Now it's time to validate activation status, created on the server
    PATSActivationStatus * serverActivationStatus = [_testServerApi getActivationStatus:activationData.activationId challenge:nil];
    result = serverActivationStatus != nil;
    if (!result) {
        return nil;
    }
    XCTAssertTrue([serverActivationStatus.activationName isEqualToString:_testServerConfig.userActivationName]);
    // Test whether the device's public key fingerprint is equal on server and client.
    XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationResult.activationFingerprint]);
    XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:_sdk.activationFingerprint]);
    XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationFingerprintBeforeCommit]);
    
    _currentActivation = [[PowerAuthSdkActivation alloc] initWithActivationData:activationData
                                                                    credentials:auth
                                                               activationResult:activationResult];
    
    // This is just a cleanup. If remove will fail, then we don't report an error
    if (removeAfter || !result) {
        if (!result) {
            NSLog(@"We're removing activation due to fact, that session creation failed.");
        }
        [_testServerApi removeActivation:activationData.activationId];
        [_currentActivation setAlreadyRemoved];
    }
    return _currentActivation;
}

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
                               activationOtp:(NSString*)activationOtp
                                 removeAfter:(BOOL)removeAfter
{
    TestActivationFlags flags = (useSignature ? TestActivationFlags_UseSignature : 0) |
                                (removeAfter ? TestActivationFlags_RemoveAfter : 0);
    return [self createActivationWithFlags:flags activationOtp:activationOtp];
}

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature removeAfter:(BOOL)removeAfter
{
    return [self createActivation:useSignature activationOtp:nil removeAfter:removeAfter];
}

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
{
    return [self createActivation:useSignature activationOtp:nil removeAfter:NO];
}

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
                               activationOtp:(NSString*)activationOtp
{
    return [self createActivation:useSignature activationOtp:activationOtp removeAfter:NO];
}

- (PowerAuthSdkActivation*) assignCustomActivationData:(PATSInitActivationResponse*)activationData
                                      activationResult:(PowerAuthActivationResult*)activationResult
                                           credentials:(PowerAuthAuthentication*)credentials
{
    if (!activationData || !activationResult || !credentials) {
        return nil;
    }
    _currentActivation = [[PowerAuthSdkActivation alloc] initWithActivationData:activationData
                                                                    credentials:[credentials copy]
                                                               activationResult:activationResult];
    return _currentActivation;
}

- (void) cleanup
{
    BOOL localCleanup = [_sdk hasValidActivation] || [_sdk hasPendingActivation];
    BOOL remoteCleanup = YES;
    if (localCleanup) {
        if (_sdk.lastFetchedActivationStatus.state == PowerAuthActivationState_Removed) {
            remoteCleanup = NO;
        }
    }
    if (remoteCleanup) {
        NSString * activationId = _currentActivation.activationData.activationId;
        if (!activationId) {
            activationId = _sdk.activationIdentifier;
        }
        if (activationId) {
            [_testServerApi removeActivation:activationId];
        }
    }
    if (localCleanup) {
        [_sdk removeActivationLocal];
    }
    [_currentActivation setAlreadyRemoved];
    _currentActivation = nil;
}

- (PowerAuthSDK*) reCreateSdkInstanceWithConfiguration:(PowerAuthConfiguration*)configuration
                        keychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration
                          clientConfiguration:(PowerAuthClientConfiguration*)clientConfiguration
{
    if (configuration == nil) {
        configuration = [_sdk.configuration copy];
    }
    if (keychainConfiguration == nil) {
        keychainConfiguration = [_sdk.keychainConfiguration copy];
    }
    if (clientConfiguration == nil) {
        clientConfiguration = [_sdk.clientConfiguration copy];
    }
    _sdk = [[PowerAuthSDK alloc] initWithConfiguration:configuration
                                 keychainConfiguration:keychainConfiguration
                                   clientConfiguration:clientConfiguration];
    return _sdk;
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
        id<PowerAuthOperationTask> task = [_sdk getActivationStatusWithCallback:^(PowerAuthActivationStatus * status,NSError * error) {
            activationStatusCustomObject = status.customObject;
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

#pragma mark - Utils

- (NSArray<NSString*>*) veryStrongPasswords
{
    return @[ @"supersecure", @"nbusr123", @"8520", @"pa55w0rd" ];
}

/**
 Creates a new PowerAuthAuthentication object with default configuration.
 */
- (PowerAuthAuthentication*) createAuthentication
{
    NSArray<NSString*> * veryCleverPasswords = [self veryStrongPasswords];
    NSString * newPassword = veryCleverPasswords[arc4random_uniform((uint32_t)veryCleverPasswords.count)];
    return [PowerAuthAuthentication commitWithPassword:newPassword];
}

/**
 Creates a new PowerAuthAuthentication object with default configuration.
 */
- (PowerAuthAuthentication*) createAuthenticationWithBiometry
{
    NSArray<NSString*> * veryCleverPasswords = [self veryStrongPasswords];
    NSString * newPassword = veryCleverPasswords[arc4random_uniform((uint32_t)veryCleverPasswords.count)];
    return [PowerAuthAuthentication commitWithPasswordAndBiometry:newPassword];
}

/**
 Validates password on server. Returns YES if password is valid.
 */
- (BOOL) checkForPassword:(NSString*)password
{
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk validatePassword:password callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    return result;
}

/**
 Validates password on server. Returns YES if password is valid.
 */
- (BOOL) checkForCorePassword:(PowerAuthCorePassword*)password
{
    BOOL result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        id<PowerAuthOperationTask> task = [_sdk validateCorePassword:password callback:^(NSError * error) {
            [waiting reportCompletion:@(error == nil)];
        }];
        XCTAssertNotNil(task);
    }] boolValue];
    return result;
}

#pragma mark - Signatures

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
    if (auth.password) {
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
        local_auth = [local_auth copyCrippledForSigning];
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

#pragma mark - Tokens

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
        error = ![result[@"version"] isEqualToString:PA_Ver];
        XCTAssertFalse(error, @"Unknown PA Token version");
    }
    return error ? nil : result;
}

- (BOOL) validateTokenHeader:(PowerAuthAuthorizationHttpHeader*)header
                activationId:(NSString*)activationId
              expectedResult:(BOOL)expectedResult
{
    NSDictionary * parsedHeader = [self parseTokenHeaderValue:header.value];
    XCTAssertNotNil(parsedHeader);
    PATSTokenValidationRequest * validationRequest = [[PATSTokenValidationRequest alloc] init];
    validationRequest.tokenIdentifier   = parsedHeader[@"token_id"];
    validationRequest.tokenDigest       = parsedHeader[@"token_digest"];
    validationRequest.nonce             = parsedHeader[@"nonce"];
    validationRequest.timestamp         = parsedHeader[@"timestamp"];
    PATSTokenValidationResponse * validationResponse = [_testServerApi validateTokenRequest:validationRequest];
    XCTAssertTrue(validationResponse.tokenValid == expectedResult);
    if (expectedResult) {
        XCTAssertTrue([validationResponse.activationId isEqualToString:activationId]);
        XCTAssertTrue([validationResponse.applicationId isEqualToString:_testServerApi.appDetail.applicationId]);
    }
    return validationResponse.tokenValid;
}

@end


@implementation PowerAuthAuthentication (TestHelper)

- (PowerAuthAuthentication*) copyForSigning
{
    if (self.password == nil) {
        @throw [NSException exceptionWithName:@"TestError" reason:@"Wrong PowerAuthAuthentication object" userInfo:nil];
    }
    return [PowerAuthAuthentication possessionWithCorePassword:self.password];
}

- (PowerAuthAuthentication*) copyCrippledForSigning
{
    // cripple auth object
    if (self.password) {
        return [PowerAuthAuthentication possession];
    } else {
        return [PowerAuthAuthentication possessionWithPassword:@"alwaysBadPassword"];
    }
}

@end
