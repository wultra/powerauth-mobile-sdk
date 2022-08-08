/**
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

#import "PA2WatchRemoteTokenProvider.h"
#import "PowerAuthWCSessionManager+Private.h"
#import "PA2WCSessionPacket_TokenData.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateMacros.h"
#import "PA2SimpleCancelable.h"

#import <PowerAuth2ForWatch/PowerAuthErrorConstants.h>
#import <PowerAuth2ForWatch/PowerAuthConfiguration.h>

@implementation PA2WatchRemoteTokenProvider
{
    PowerAuthConfiguration * _configuration;
    NSString * _target;
}

#pragma mark - PA2PrivateRemoteTokenProvider

- (BOOL) authenticationIsRequired
{
    return NO;
}

- (void) prepareInstanceForConfiguration:(nonnull PowerAuthConfiguration*)configuration
{
    _configuration = configuration;
    _target = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:_configuration.instanceId];
}


- (nullable id<PowerAuthOperationTask>) requestTokenWithName:(nonnull NSString*)name
                                              authentication:(nullable PowerAuthAuthentication*)authentication
                                                  completion:(nonnull void(^)(PA2PrivateTokenData * _Nullable tokenData, NSError * _Nullable error))completion
{
    //
    // Remote request for token, with using WatchConnectivity framework
    //
    PA2WCSessionPacket_TokenData * requestData = [[PA2WCSessionPacket_TokenData alloc] init];
    requestData.command   = PA2WCSessionPacket_CMD_TOKEN_GET;
    requestData.tokenName = name;
    PA2WCSessionPacket * packet = [PA2WCSessionPacket packetWithData:requestData target:_target];
    
    id<PowerAuthOperationTask> task = [[PA2SimpleCancelable alloc] init];
    PowerAuthWCSessionManager * manager = [PowerAuthWCSessionManager sharedInstance];
    [manager sendPacketWithResponse:packet responseClass:requestData.class completion:^(PA2WCSessionPacket *response, NSError *error) {
        //
        if (task.isCancelled) {
            return;
        }
        //
        PA2PrivateTokenData * tokenData = nil;
        if (!error) {
            PA2WCSessionPacket_TokenData * responseData = PA2ObjectAs(response.payload, PA2WCSessionPacket_TokenData);
            if ([responseData.command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_PUT]) {
                if (!responseData.tokenNotFound) {
                    tokenData = [PA2PrivateTokenData deserializeWithData:responseData.tokenData];
                    if (!tokenData) {
                        error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WatchRemoteTokenProvider: Wront token data received.");
                    }
                } else {
                    error = PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Token not found on paired iPhone.");
                }
            } else {
                error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WatchRemoteTokenProvider: Wront command received.");
            }
        }
        completion(tokenData, error);
    }];
    return task;
}

- (nullable id<PowerAuthOperationTask>) removeTokenData:(nonnull PA2PrivateTokenData*)tokenData
                                             completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion
{
    completion(NO, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Removing token on iPhone is unsupported operation"));
    return nil;
}

@end
