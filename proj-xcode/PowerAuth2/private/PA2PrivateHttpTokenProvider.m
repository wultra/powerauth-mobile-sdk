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

#import "PA2HttpClient.h"
#import "PA2RestApiEndpoint.h"

#import "PA2GetTokenResponse.h"
#import "PA2RemoveTokenRequest.h"

#import <PowerAuth2/PowerAuthAuthentication.h>

@implementation PA2PrivateHttpTokenProvider

- (id) initWithHttpClient:(PA2HttpClient *)httpClient
{
    self = [super init];
    if (self) {
        _httpClient = httpClient;
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
    return [_httpClient postObject:nil
                                to:[PA2RestApiEndpoint getToken]
                              auth:authentication
                        completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                            // Completion from HTTP networking
                            PA2PrivateTokenData * tokenData = nil;
                            if (response) {
                                PA2GetTokenResponse * ro = response;
                                tokenData = [[PA2PrivateTokenData alloc] init];
                                tokenData.identifier = ro.tokenId;
                                tokenData.name = name;
                                tokenData.secret = ro.tokenSecret ? [[NSData alloc] initWithBase64EncodedString:ro.tokenSecret options:0] : nil;
                                if (!tokenData.hasValidData) {
                                    // Throw away that object...
                                    tokenData = nil;
                                }
                            }
                            if (!tokenData && !error) {
                                // Create fallback error in case that token has not been created.
                                error =  PA2MakeError(PowerAuthErrorCode_Encryption, nil);
                            }
                            // Call back to the application
                            completion(tokenData, error);
                        }];
}

- (id<PowerAuthOperationTask>) removeTokenData:(PA2PrivateTokenData*)tokenData
                                    completion:(void(^)(BOOL removed, NSError * error))completion
{
    PA2RemoveTokenRequest * removeRequest = [[PA2RemoveTokenRequest alloc] init];
    removeRequest.tokenId = tokenData.identifier;
    return [_httpClient postObject:removeRequest
                                to:[PA2RestApiEndpoint removeToken]
                              auth:[PowerAuthAuthentication possession]
                        completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                            // Completion from HTTP networking
                            BOOL removed = (status == PowerAuthRestApiResponseStatus_OK) && (error == nil);
                            completion(removed, error);
                        }];
}

@end
