/*
 * Copyright 2024 Wultra s.r.o.
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

#import "PA2GetTemporaryKeyTask.h"
#import "PA2HttpClient.h"
#import "PA2RestApiEndpoint.h"
#import "PA2JwtObject.h"
#import "PA2GetTemporaryKeyRequest.h"
#import "PA2GetTemporaryKeyResponse.h"
#import "PA2ObjectSerialization.h"
#import "PA2PrivateMacros.h"

@implementation PA2GetTemporaryKeyTask
{
    PA2HttpClient * _client;
    id<PowerAuthCoreSessionProvider> _sessionProvider;
    __weak id<PA2GetTemporaryKeyTaskDelegate> _delegate;
    NSData * _deviceRelatedKey;
    BOOL _isApplicationScope;
}

- (instancetype) initWithHttpClient:(PA2HttpClient*)httpClient
                    sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                         sharedLock:(id<NSLocking>)sharedLock
                     applicationKey:(NSString*)applicationKey
                   deviceRelatedKey:(NSData*)deviceRelatedKey
                     encryptorScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope
                           delegate:(id<PA2GetTemporaryKeyTaskDelegate>)delegate
{
    BOOL isAppScope = encryptorScope ==  PowerAuthCoreEciesEncryptorScope_Application;
    self = [super initWithSharedLock:sharedLock
                            taskName:isAppScope ? @"GetTempKey-App" : @"GetTempKey-Act"];
    if (self) {
        _client = httpClient;
        _sessionProvider = sessionProvider;
        _deviceRelatedKey = deviceRelatedKey;
        _encryptorScope = encryptorScope;
        _delegate = delegate;
        _isApplicationScope = isAppScope;
    }
    return self;
}

- (void) onTaskStart
{
    [super onTaskStart];
    
    PA2GetTemporaryKeyRequest * request = [[PA2GetTemporaryKeyRequest alloc] init];
    PA2JwtObject * requestJwt = [self prepareRequestJwt:request];
    if (!requestJwt) {
        return;
    }
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint getTemporaryKey];
    id<PowerAuthOperationTask> cancelable = [_client postObject:requestJwt to:endpoint completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError * error) {
        PA2GetTemporaryKeyResponse * objectResponse = nil;
        if (status == PowerAuthRestApiResponseStatus_OK && response) {
            // Note that response is already PA2JwtObject. We're using the casting because the completion closure cannot use such type, due to a bug in objc compiler.
            // If objective-c class implements more than one protocol (in this case PA2Decodable and PA2Encodable), then "magic" casting to a right closure type doesn't work,
            // even if the requested protocol is implemented by the class.
            objectResponse = [self processResponseJwt:(PA2JwtObject*)response error:&error];
            if (objectResponse && ![self validateResponse:objectResponse withRequest:request]) {
                error = PA2MakeError(PowerAuthErrorCode_Encryption, @"JWT response doesn't match request");
                objectResponse = nil;
            }
        }
        [self complete:objectResponse error:error];
    }];
    [self replaceCancelableOperation:cancelable];
}

- (void) onTaskCompleteWithResult:(id)result error:(NSError*)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getTemporaryKeyTask:self didFinishWithResponse:result error:error];
}



#pragma mark - Request

- (PA2JwtObject*) prepareRequestJwt:(PA2GetTemporaryKeyRequest*)request
{
    return [_sessionProvider readTaskWithSession:^PA2JwtObject*(PowerAuthCoreSession * session) {
        NSString * activationId;
        if (_isApplicationScope) {
            activationId = nil;
        } else {
            activationId = _sessionProvider.activationIdentifier;
            if (!activationId) {
                [self complete:nil error:PA2MakeError(PowerAuthErrorCode_MissingActivation, nil)];
                return nil;
            }
        }
        // Update input request object
        request.appKey = _applicationKey;
        request.activationId = activationId;
        request.challenge = [[PowerAuthCoreCryptoUtils randomBytes:18] base64EncodedStringWithOptions:0];
        // Prepare JWT string
        NSString * jwtHeader = @"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.";     // {"alg":"HS256","typ":"JWT"} with dot separator
        NSString * jwtPayload = [PA2ObjectSerialization serializeJwtObject:request];
        NSString * jwtSignedData = [jwtHeader stringByAppendingString:jwtPayload];
        PowerAuthCoreSignedData * dataToSign = [[PowerAuthCoreSignedData alloc] init];
        dataToSign.data = [jwtSignedData dataUsingEncoding:NSASCIIStringEncoding];
        dataToSign.signingDataKey = _isApplicationScope ? PowerAuthCoreSigningDataKey_HMAC_Application : PowerAuthCoreSigningDataKey_HMAC_Activation;
        if (![session signDataWithHmacKey:dataToSign keys:[self signatureUnlockKeys]]) {
            [self complete:nil error:PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to calculate JWT signature")];
            return nil;
        }
        NSString * jwtString = [[jwtSignedData stringByAppendingString:@"."] stringByAppendingString:[dataToSign.signature jwtEncodedString]];
        return [[PA2JwtObject alloc] initWithJwt:jwtString];
    }];
}

- (PowerAuthCoreSignatureUnlockKeys*) signatureUnlockKeys
{
    if (_isApplicationScope) {
        return nil;
    }
    PowerAuthCoreSignatureUnlockKeys * keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
    keys.possessionUnlockKey = _deviceRelatedKey;
    return keys;
}


#pragma mark - Response

- (PA2GetTemporaryKeyResponse*) processResponseJwt:(PA2JwtObject*)responseJwt error:(NSError**)error
{
    NSString * jwtString = responseJwt.jwt;
    if (!jwtString) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Empty JWT response");
        return nil;
    }
    NSArray * jwtComponents = [jwtString componentsSeparatedByString:@"."];
    if (jwtComponents.count != 3) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Invalid JWT response");
        return nil;
    }
    NSString * jwtHeader = jwtComponents[0];
    NSString * jwtPayload = jwtComponents[1];
    NSString * jwtSignature = jwtComponents[2];
    if (jwtHeader.length == 0 || jwtPayload.length == 0 || jwtSignature.length == 0) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Invalid JWT response");
        return nil;
    }
    PA2JwtHeader * jwtHeaderObj = (PA2JwtHeader*)[PA2ObjectSerialization deserializeJwtObject:jwtHeader forClass:[PA2JwtHeader class] error:nil];
    if (!jwtHeaderObj) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Invalid JWT header in response");
        return nil;
    }
    if (![jwtHeaderObj.typ isEqualToString:@"JWT"]) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Unsupported JWT response");
    }
    if (![jwtHeaderObj.alg isEqualToString:@"ES256"]) {
        *error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Unsupported JWT algorithm in response");
        return nil;
    }
    PowerAuthCoreSignedData * signedData = [[PowerAuthCoreSignedData alloc] init];
    signedData.data = [[[jwtHeader stringByAppendingString:@"."] stringByAppendingString:jwtPayload] dataUsingEncoding:NSASCIIStringEncoding];
    signedData.signature = [[NSData alloc] initWithJwtEncodedString:jwtSignature];
    signedData.signingDataKey = _isApplicationScope ? PowerAuthCoreSigningDataKey_ECDSA_MasterServerKey : PowerAuthCoreSigningDataKey_ECDSA_PersonalizedKey;
    BOOL valid = [_sessionProvider readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        return [session verifyServerSignedData:signedData];
    }];
    if (!valid) {
        *error = PA2MakeError(PowerAuthErrorCode_Encryption, @"Invalid signature in JWT response");
        return nil;
    }
    return [PA2ObjectSerialization deserializeJwtObject:jwtPayload forClass:[PA2GetTemporaryKeyResponse class] error:error];
}

- (BOOL) validateResponse:(PA2GetTemporaryKeyResponse*)response withRequest:(PA2GetTemporaryKeyRequest*)request
{
    BOOL match = [response.challenge isEqualToString:request.challenge];
    match = match && [response.appKey isEqualToString:request.appKey];
    if (!_isApplicationScope) {
        match = match && [response.activationId isEqualToString:request.activationId];
    }
    return match;
}

@end
