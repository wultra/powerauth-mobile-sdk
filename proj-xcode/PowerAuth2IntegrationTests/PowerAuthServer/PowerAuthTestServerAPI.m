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

#import "PowerAuthTestServerAPI.h"
#import "RestHelper.h"

@import PowerAuthCore;

@implementation PowerAuthTestServerAPI
{
    NSURL * _testServerUrl;
    RestHelper * _rest;
}

#pragma mark - Object initilization

- (id) initWithConfiguration:(PowerAuthTestServerConfig*)testServerConfig
{
    self = [super init];
    if (self) {
        _testServerConfig = testServerConfig;
        _testServerUrl = [NSURL URLWithString:testServerConfig.serverApiUrl];
        _applicationNameString = testServerConfig.powerAuthAppName;
        _applicationVersionString = testServerConfig.powerAuthAppVersion;
        
        NSBundle * mainBundle = [NSBundle bundleForClass:[self class]];        
        NSURL * restBundleUrl = [mainBundle URLForResource:@"RestEndpoints" withExtension:@"bundle"];
        NSBundle * restBundle = [NSBundle bundleWithURL:restBundleUrl];
        _rest = [[RestHelper alloc] initWithBundle:restBundle config:testServerConfig];
    }
    return self;
}

- (BOOL) validateConnection
{
    _hasValidConnection = NO;
    
    PATSSystemStatus * systemStatus = [self getSystemStatus];
    if (![systemStatus.status isEqualToString:@"OK"]) {
        NSLog(@"System status is not OK, but '%@'", systemStatus.status);
        return NO;
    }
    _testServerConfig.serverApiVersion = [_rest applyServerVersion:systemStatus.version];
    _testServerConfig.serverMaxProtovolVersion = PATSProtoVer(_testServerConfig.serverApiVersion);
    _serverVersion = _testServerConfig.serverApiVersion;
    
    NSArray<PATSApplication*>* applicationList = [self getApplicationList];
    __block PATSApplication * foundRequiredApp = nil;
    [applicationList enumerateObjectsUsingBlock:^(PATSApplication * app, NSUInteger idx, BOOL * stop) {
        if ([app.applicationName isEqualToString:_applicationNameString]) {
            foundRequiredApp = app;
            *stop = YES;
        }
    }];
    if (!foundRequiredApp) {
        // Version not found,
        foundRequiredApp = [self createApplication:_applicationNameString];
    }
    // Get Application detail
    _appDetail = [self getApplicationDetail:foundRequiredApp.applicationId];
    // Look for appropriate version
    [_appDetail.versions enumerateObjectsUsingBlock:^(PATSApplicationVersion * obj, NSUInteger idx, BOOL * stop) {
        if ([obj.applicationVersionName isEqualToString:_applicationVersionString]) {
            _appVersion = obj;
            *stop = YES;
        }
    }];
    //
    if (!_appVersion) {
        // We need to create requested app version
        _appVersion = [self createApplicationVersion:_appDetail.applicationId versionName:_applicationVersionString];
        
    }
    if (![_appDetail.applicationName isEqualToString:_applicationNameString]) {
        NSLog(@"Application name doesn't match: %@ vs %@", _appDetail.applicationName, _applicationNameString);
        return NO;
    }
    if (![_appVersion.applicationVersionName isEqualToString:_applicationVersionString]) {
        NSLog(@"Application version name doesn't match: %@ vs %@", _appVersion.applicationVersionName, _applicationVersionString);
        return NO;
    }
    if (!_appVersion.supported) {
        NSLog(@"Application version '%@' is not supported", _appVersion.applicationVersionName);
        return NO;
    }
    
    _hasValidConnection = YES;
    
    return YES;
}

- (void) checkForValidConnection
{
    if (!_hasValidConnection) {
        @throw [NSException exceptionWithName:@"RestError" reason:@"API object has no valid connection to the server." userInfo:nil];
    }
}

#pragma mark - System status

- (PATSSystemStatus*) getSystemStatus
{
    return [_rest request:@"GetSystemStatus" params:nil];
}

////////////////////////////

- (NSArray<PATSApplication*>*) getApplicationList
{
    return [_rest request:@"GetApplicationList" params:nil];
}

- (PATSApplicationDetail*) getApplicationDetail:(NSString*)applicationId
{
    return [_rest request:@"GetApplicationDetail" params:@[applicationId]];
}

- (PATSApplication*) createApplication:(NSString*)applicationName
{
    return [_rest request:@"CreateApplication" params:@[applicationName]];
}

#pragma mark - SOAP Application Versions

- (PATSApplicationVersion*) createApplicationVersion:(NSString*)applicationId versionName:(NSString*)versionName
{
    return [_rest request:@"CreateApplicationVersion" params:@[applicationId, versionName]];
}

- (PATSApplicationVersion*) createApplicationVersionIfDoesntExist:(NSString*)versionName
{
    [self checkForValidConnection];
    // Update app detail
    _appDetail = [self getApplicationDetail:_appDetail.applicationId];
    // Look for version
    __block PATSApplicationVersion * response = nil;
    [_appDetail.versions enumerateObjectsUsingBlock:^(PATSApplicationVersion * obj, NSUInteger idx, BOOL * stop) {
        if ([obj.applicationVersionName isEqualToString:versionName]) {
            if (obj.supported) {
                response = obj;
                *stop = YES;
            }
        }
    }];
    if (!response) {
        response = [self createApplicationVersion:_appDetail.applicationId versionName:versionName];
    }
    return response;
}

- (BOOL) supportApplicationVersion:(NSString*)applicationVersionId
{
    NSArray * params = _serverVersion < PATS_V1_3 ? @[applicationVersionId] : @[_appDetail.applicationId, applicationVersionId];
    PATSApplicationVersionSupport * response = [_rest request:@"SupportApplicationVersion" params:params];
    BOOL result = response.supported == YES;
    if (!result) {
        NSLog(@"Changing version '%@' status to 'supported' failed.", applicationVersionId);
    }
    return result;
}

- (BOOL) unsupportApplicationVersion:(NSString*)applicationVersionId
{
    NSArray * params = _serverVersion < PATS_V1_3 ? @[applicationVersionId] : @[_appDetail.applicationId, applicationVersionId];
    PATSApplicationVersionSupport * response = [_rest request:@"UnsupportApplicationVersion" params:params];
    BOOL result = response.supported == NO;
    if (!result) {
        NSLog(@"Changing version '%@' status to 'unsupported' failed.", applicationVersionId);
    }
    return result;
}

#pragma mark - SOAP Activation

- (PATSInitActivationResponse*) initializeActivation:(NSString *)userId
{
    return [self initializeActivation:userId
                        otpValidation:PATSActivationOtpValidation_NONE
                                  otp:nil];
}

- (PATSInitActivationResponse*) initializeActivation:(NSString *)userId
                                       otpValidation:(PATSActivationOtpValidationEnum)otpValidation
                                                 otp:(NSString*)otp;
{
    [self checkForValidConnection];
    NSArray * params;
    if (otpValidation != PATSActivationOtpValidation_NONE && otp.length > 0) {
        params = @[userId, _appDetail.applicationId, PATSActivationOtpValidationEnumToString(otpValidation), otp];
    } else {
        params = @[userId, _appDetail.applicationId];
    }
    PATSInitActivationResponse * response = [_rest request:@"ActivationInit" params:params];
    response.activationIdShort = [response.activationCode substringToIndex:11];
    response.activationOTP     = [response.activationCode substringFromIndex:12];
    return response;
}

- (BOOL) removeActivation:(NSString *)activationId
{
    return [self removeActivation:activationId revokeRecoveryCodes:NO];
}

- (BOOL) removeActivation:(NSString*)activationId revokeRecoveryCodes:(BOOL)revokeRecoveryCodes
{
    [self checkForValidConnection];
    NSDictionary * response = [_rest request:@"ActivationRemove" params:@[activationId, @(revokeRecoveryCodes)]];
    if (![response[@"removed"] boolValue]) {
        NSLog(@"The requested activation '%@' was not removed.", activationId);
        return NO;
    }
    return YES;
}

static PATSActivationStatusEnum _String_to_ActivationStatusEnum(NSString * str)
{
    if ([str isEqualToString:@"CREATED"]) {
        return PATSActivationStatus_CREATED;
    } else if ([str isEqualToString:@"PENDING_COMMIT"]) {
        return PATSActivationStatus_PENDING_COMMIT;
    } else if ([str isEqualToString:@"ACTIVE"]) {
        return PATSActivationStatus_ACTIVE;
    } else if ([str isEqualToString:@"BLOCKED"]) {
        return PATSActivationStatus_BLOCKED;
    } else if ([str isEqualToString:@"REMOVED"]) {
        return PATSActivationStatus_REMOVED;
    }
    return PATSActivationStatus_Unknown;
}

- (PATSActivationStatus*) getActivationStatus:(NSString*)activationId challenge:(NSString*)challenge
{
    [self checkForValidConnection];
    NSArray * params = challenge == nil ? @[activationId]  : @[activationId, challenge];
    PATSActivationStatus * response = [_rest request:@"ActivationStatus" params:params];
    response.activationStatusEnum = _String_to_ActivationStatusEnum(response.activationStatus);
    return response;
}

- (PATSActivationStatus*) getActivationStatus:(NSString*)activationId
{
    return [self getActivationStatus:activationId challenge:nil];
}

- (PATSSimpleActivationStatus*) blockActivation:(NSString*)activationId
{
    [self checkForValidConnection];
    PATSSimpleActivationStatus * response = [_rest request:@"ActivationBlock" params:@[activationId]];
    response.activationStatusEnum = _String_to_ActivationStatusEnum(response.activationStatus);
    return response;
}

- (PATSSimpleActivationStatus*) unblockActivation:(NSString*)activationId;
{
    [self checkForValidConnection];
    PATSSimpleActivationStatus * response = [_rest request:@"ActivationUnblock" params:@[activationId]];
    response.activationStatusEnum = _String_to_ActivationStatusEnum(response.activationStatus);
    return response;
}

- (BOOL) commitActivation:(NSString*)activationId
{
    [self checkForValidConnection];
    NSDictionary * response = [_rest request:@"ActivationCommit" params:@[activationId]];
    if (![response[@"activated"] boolValue]) {
        NSLog(@"The requested activation '%@' was not commited.", activationId);
        return NO;
    }
    return YES;
}

#pragma mark - SOAP Signatures

- (PATSVerifySignatureResponse*) verifySignature:(NSString*)activationId
                                            data:(NSString*)normalizedData
                                       signature:(NSString*)signature
                                   signatureType:(NSString*)signatureType
                                signatureVersion:(NSString*)signatureVersion
{
    [self checkForValidConnection];
    NSArray * params = @[activationId, _appVersion.applicationKey, normalizedData, signature, signatureType.uppercaseString, signatureVersion];
    PATSVerifySignatureResponse * response = [_rest request:@"VerifySignature" params:params];
    response.activationStatusEnum   = _String_to_ActivationStatusEnum(response.activationStatus);
    return response;
}

- (NSString*) normalizeDataForSignatureWithMethod:(NSString*)httpMethod
                                            uriId:(NSString*)uriId
                                            nonce:(NSString*)nonceB64
                                             data:(NSData*)data
{
    NSString * dataB64 = [data base64EncodedStringWithOptions:0];
    NSString * uriIdB64 = [[uriId dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    NSArray * components = @[httpMethod, uriIdB64, nonceB64, dataB64 ];
    return [components componentsJoinedByString:@"&"];
}

- (PATSOfflineSignaturePayload*) createNonPersonalizedOfflineSignaturePayload:(NSString*)applicationId
                                                                         data:(NSString*)data
{
    [self checkForValidConnection];
    return [_rest request:@"CreateNonPersonalizedOfflineSignaturePayload" params:@[applicationId, data]];
}

- (PATSOfflineSignaturePayload*) createPersonalizedOfflineSignaturePayload:(NSString*)activationId
                                                                      data:(NSString*)data
{
    [self checkForValidConnection];
    return [_rest request:@"CreatePersonalizedOfflineSignaturePayload" params:@[activationId, data]];
}

- (PATSVerifySignatureResponse*) verifyOfflineSignature:(NSString*)activationId
                                                   data:(NSString*)dataHash
                                              signature:(NSString*)signature
                                          allowBiometry:(BOOL)allowBiometry
{
    [self checkForValidConnection];
    PATSVerifySignatureResponse * response = [_rest request:@"VerifyOfflineSignature" params:@[activationId, dataHash, signature, @(allowBiometry)]];
    response.activationStatusEnum = _String_to_ActivationStatusEnum(response.activationStatus);
    return response;
}

- (BOOL) verifyECDSASignature:(NSString*)activationId data:(NSData*)data signature:(NSData*)signature
{
    NSString * dataB64 = [data base64EncodedStringWithOptions:0];
    NSString * signatureB64 = [signature base64EncodedStringWithOptions:0];
    NSDictionary * response = [_rest request:@"VerifyECDSASignature" params:@[activationId, dataB64, signatureB64]];
    return [response[@"signatureValid"] boolValue];
}


#pragma mark - Tokens

- (PATSTokenValidationResponse*) validateTokenRequest:(PATSTokenValidationRequest*)request
{
    [self checkForValidConnection];
    NSArray * params;
    if (_testServerConfig.serverMaxProtovolVersion >= PATS_P32) {
        params = @[ request.tokenIdentifier, request.tokenDigest, request.nonce, request.timestamp, request.protocolVersion];
    } else {
        params = @[ request.tokenIdentifier, request.tokenDigest, request.nonce, request.timestamp];
    }
    return [_rest request:@"TokenValidate" params:params];
}

@end
