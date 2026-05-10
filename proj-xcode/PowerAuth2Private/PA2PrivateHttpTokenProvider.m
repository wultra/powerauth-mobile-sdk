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

#import "PA2PrivateHttpTokenProvider.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateMacros.h"

#import "PA2CoreHttpClient.h"

#import "PowerAuthAuthentication.h"

@implementation PA2PrivateHttpTokenProvider
{
    __weak id<PA2CoreCredentialsResolver> _credentialsResolver;
}
- (id) initWithHttpClient:(PA2CoreHttpClient *)httpClient
      credentialsResolver:(id<PA2CoreCredentialsResolver>)credentialsResolver
{
    self = [super init];
    if (self) {
        _httpClient = httpClient;
        _credentialsResolver = credentialsResolver;
    }
    return self;
}

- (BOOL) authenticationIsRequired
{
    return YES;
}

- (void) prepareInstanceForConfiguration:(PowerAuthConfiguration *)configuration
{
    // EMPTY
}

- (id<PowerAuthOperationTask>) requestTokenWithName:(NSString *)name
                                     authentication:(PowerAuthAuthentication *)authentication
                                         completion:(void (^)(PA2PrivateTokenData *, NSError *))completion
{
    NSError * localError = nil;
    PowerAuthCoreCredentials * credentials = [_credentialsResolver resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        completion(nil, localError);
        return nil;
    }
    if (!credentials) {
        completion(nil, PA2MakeError(PowerAuthErrorCode_Other, @"PowerAuthSDK instance is no longer valid"));
        return nil;
    }
    __block NSString * activationIdentifier = nil;
    PowerAuthCoreRequest* request = [_httpClient.sessionInterface readTaskWithSession:^PowerAuthCoreRequest*(PowerAuthCoreSession* session, NSError** error) {
        activationIdentifier = session.activationIdentifier;
        return [session createAccessToken:credentials error:error];
    } error:&localError];
    if (localError) {
        completion(nil, localError);
        return nil;
    }
    return [_httpClient postCoreRequest:request completion:^(PowerAuthCoreRequest * request, PowerAuthCoreTokenData* response, NSError * error) {
        PA2PrivateTokenData * tokenData = nil;
        if (response) {
            tokenData = [[PA2PrivateTokenData alloc] init];
            tokenData.identifier = response.tokenIdentifier;
            tokenData.name = name;
            tokenData.secret = response.tokenSecret;
            tokenData.activationIdentifier = activationIdentifier;
            tokenData.authenticationFactors = response.authenticationFactorMask;
            if (!tokenData.hasValidData) {
                tokenData = nil;
                error = PA2MakeError(PowerAuthErrorCode_Encryption, @"Invalid token data received from the server");
            }
        }
        completion(tokenData, error);
    }];
}

- (id<PowerAuthOperationTask>) removeTokenData:(PA2PrivateTokenData*)tokenData
                                    completion:(void(^)(BOOL removed, NSError * error))completion
{
    NSError* localError = nil;
    PowerAuthCoreRequest* request = [_httpClient.sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession* session, NSError** error) {
        return [session removeAccessToken:tokenData.identifier error:error];
    } error:&localError];
    if (localError) {
        completion(NO, localError);
    }
    return [_httpClient postCoreRequest:request completion:^(PowerAuthCoreRequest * request, id  response, NSError * error) {
        completion(error == nil, error);
    }];
}

@end
