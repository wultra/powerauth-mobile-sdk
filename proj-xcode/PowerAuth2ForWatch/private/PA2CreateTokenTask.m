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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2CreateTokenTask.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateTokenTask
{
    __weak id<PA2PrivateRemoteTokenProvider> _tokenProvider;
    __weak id<PowerAuthPrivateTokenStore> _tokenStore;
    NSString * _tokenName;
    NSString * _activationId;
    PowerAuthAuthentication * _authentication;
}

- (id) initWithProvider:(id<PA2PrivateRemoteTokenProvider>)provider
             tokenStore:(id<PowerAuthPrivateTokenStore>)tokenStore
         authentication:(PowerAuthAuthentication*)authentication
           activationId:(NSString*)activationId
              tokenName:(NSString*)tokenName
             sharedLock:(id<NSLocking>)sharedLock
{
    self = [super initWithSharedLock:sharedLock taskName:@"CreateToken"];
    if (self) {
        _tokenProvider = provider;
        _tokenStore = tokenStore;
        _activationId = activationId;
        _tokenName = tokenName;
        _authentication = authentication;
    }
    return self;
}

- (void) onTaskStart
{
    [super onTaskStart];
    
    id<PowerAuthOperationTask> task = [_tokenProvider requestTokenWithName:_tokenName authentication:_authentication completion:^(PA2PrivateTokenData * tokenData, NSError * error) {
        PowerAuthToken * token;
        id<PowerAuthPrivateTokenStore> tokenStore = _tokenStore;
        if (tokenData && tokenStore) {
            tokenData.activationIdentifier = _activationId;
            tokenData.authenticationFactors = _authentication.signatureFactorMask;
            token = [[PowerAuthToken alloc] initWithStore:tokenStore data:tokenData];
        } else {
            token = nil;
            if (!error) {
                error = PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"Token store is no longer valid.");
            }
        }
        [self complete:token error:error];
    }];
    if (task) {
        [self addCancelableOperation:task];
    } else {
        [self complete:nil error:PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"Failed to get token from remote provider.")];
    }
}

- (void) onTaskCompleteWithResult:(PowerAuthToken*)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    PA2PrivateTokenData * tokenData = result.privateTokenData;
    if (tokenData) {
        [_tokenStore storeTokenData:tokenData];
    }
    [_tokenStore removeCreateTokenTask:_tokenName];
}

@end
