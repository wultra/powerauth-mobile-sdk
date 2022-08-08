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

#import <PowerAuth2/PowerAuthSDK.h>
#import <PowerAuth2/PowerAuthLog.h>

#import "PowerAuthSDK+Private.h"
// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#import "PowerAuthWCSessionManager+Private.h"
#import "PA2WCSessionPacket_ActivationStatus.h"
#import "PA2WCSessionPacket_TokenData.h"
#import "PA2WCSessionPacket_Success.h"
#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateMacros.h"

#pragma mark - WatchSupport implementation -

@implementation PowerAuthSDK (WatchSupport)

- (PA2WCSessionPacket*) prepareActivationStatusPacket
{
    NSString * activationIdentifier = self.sessionProvider.activationIdentifier;
    NSString * instanceIdentifier   = self.privateInstanceId;
    
    if (!instanceIdentifier) {
        PowerAuthLog(@"PowerAuthSDK instance is not properly configured. PowerAuthConfiguration has no instanceId.");
        return nil;
    }
    
    NSString * target  = [PA2WCSessionPacket_SESSION_TARGET stringByAppendingString:instanceIdentifier];

    PA2WCSessionPacket_ActivationStatus * statusData = [[PA2WCSessionPacket_ActivationStatus alloc] init];
    statusData.activationId = activationIdentifier;
    statusData.command = PA2WCSessionPacket_CMD_SESSION_PUT;
    return [PA2WCSessionPacket packetWithData:statusData target:target];
}


- (BOOL) sendActivationStatusToWatch
{
    if (@available(iOS 9, *)) {
        PowerAuthWCSessionManager * manager = [PowerAuthWCSessionManager sharedInstance];
        if (manager.validSession == nil) {
            return NO;
        }
        PA2WCSessionPacket * packet = [self prepareActivationStatusPacket];
        if (!packet) {
            return NO;
        }
        [manager sendPacket:packet];
        return YES;
    }
    PowerAuthLog(@"PowerAuthSDK: Not supported on older iOS versions.");
    return NO;
}


- (void) sendActivationStatusToWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion
{
    PA2WCSessionPacket * packet = [self prepareActivationStatusPacket];
    if (packet) {
        [[PowerAuthWCSessionManager sharedInstance] sendPacketWithResponse:packet responseClass:[PA2WCSessionPacket_Success class] completion:^(PA2WCSessionPacket *response, NSError *error) {
            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(error);
                });
            }
        }];
    } else {
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(PA2MakeError(PowerAuthErrorCode_WatchConnectivity,  @"PowerAuthSDK instance is not properly configured. PowerAuthConfiguration has no instanceId."));
            });
        }
    }
}

@end



#pragma mark - PA2WCSessionDataHandler implementation -

@interface PowerAuthToken (WatchSupportPrivate)
- (PA2WCSessionPacket*) prepareTokenDataPacketForWatch;
@end

@implementation PowerAuthSDK (WatchSupportPrivate)

- (BOOL) canProcessPacket:(PA2WCSessionPacket*)packet
{
    NSString * target = packet.target;
    NSString * instanceId = self.privateInstanceId;
    NSString * statusTarget = [PA2WCSessionPacket_SESSION_TARGET stringByAppendingString:instanceId];
    if ([target isEqualToString:statusTarget]) {
        return YES;
    }
    NSString * tokenTarget = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:instanceId];
    if ([target isEqualToString:tokenTarget]) {
        return YES;
    }
    return NO;
}

- (PA2WCSessionPacket*) sessionManager:(PowerAuthWCSessionManager*)manager responseForPacket:(PA2WCSessionPacket*)packet
{
    // Handle packet received from iPhone
    NSString * target = packet.target;
    NSString * instanceId = self.privateInstanceId;
    
    NSString * statusTarget = [PA2WCSessionPacket_SESSION_TARGET stringByAppendingString:instanceId];
    if ([target isEqualToString:statusTarget]) {
        return [self processStatusResponse:packet];
    }
    NSString * tokenTarget = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:instanceId];
    if ([target isEqualToString:tokenTarget]) {
        return [self processTokenResponse:packet];
    }
    
    // Internal error. We should always process packets delivered to this method.
    NSError * error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WatchStatusService: Internal error: Packet cannot be processed here.");
    return [PA2WCSessionPacket packetWithError:error];
}

#pragma mark -

- (PA2WCSessionPacket*) processStatusResponse:(PA2WCSessionPacket*)packet
{
    NSString * errorMessage = nil;
    PA2WCSessionPacket * response = nil;
    do {
        // Deserialize payload & instanceId
        PA2WCSessionPacket_ActivationStatus * status = [[PA2WCSessionPacket_ActivationStatus alloc] initWithDictionary:packet.sourceData];
        if ([status validatePacketData]) {
            // Process command
            NSString * command = status.command;
            if ([command isEqualToString:PA2WCSessionPacket_CMD_SESSION_GET]) {
                // watch App requesting status of this object.
                response = [self prepareActivationStatusPacket];
                if (!packet.requestWithoutReplyHandler) {
                    // Reply handler is present. The target should be modified.
                    response.target = PA2WCSessionPacket_RESPONSE_TARGET;
                } else {
                    // Getting status without response handler. The target is already
                    // valid from 'prepareActivationStatusPacket' method, so just send
                    // that response back to watch.
                    response.sendLazyResponseIfPossible = YES;
                }
                //
            } else {
                errorMessage = [NSString stringWithFormat:@"PowerAuthSDK+WatchSupport: Unsupported command '%@'. Target: %@", command, packet.target];
            }
        } else {
            errorMessage = [NSString stringWithFormat:@"PowerAuthSDK+WatchSupport: Received packet has invalid data. Target: %@", packet.target];
        }
    } while (false);
    
    if (errorMessage) {
        // Reply packet with error.
        response = [PA2WCSessionPacket packetWithError:PA2MakeError(PowerAuthErrorCode_WatchConnectivity, errorMessage)];
    }
    return response;
}



- (PA2WCSessionPacket*) processTokenResponse:(PA2WCSessionPacket*)packet
{
    NSString * errorMessage = nil;
    PA2WCSessionPacket * response = nil;
    do {
        // Deserialize payload & instanceId
        PA2WCSessionPacket_TokenData * tokenRequest = [[PA2WCSessionPacket_TokenData alloc] initWithDictionary:packet.sourceData];
        if ([tokenRequest validatePacketData]) {
            // Process command
            NSString * command = tokenRequest.command;
            if ([command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_GET]) {
                // watch App requesting information about token
                if (self.hasValidActivation) {
                    PowerAuthToken * localToken = [self.tokenStore localTokenWithName: tokenRequest.tokenName];
                    if (localToken) {
                        // Prepare response with token data in payload
                        response = [localToken prepareTokenDataPacketForWatch];
                        response.target = PA2WCSessionPacket_RESPONSE_TARGET;
                    } else {
                        // Prepare "token not found" response
                        PA2WCSessionPacket_TokenData * packetData = [[PA2WCSessionPacket_TokenData alloc] init];
                        packetData.command = PA2WCSessionPacket_CMD_TOKEN_PUT;
                        packetData.tokenName = tokenRequest.tokenName;
                        packetData.tokenData = nil;
                        packetData.tokenNotFound = YES;
                        response = [PA2WCSessionPacket packetWithData:packetData target:PA2WCSessionPacket_RESPONSE_TARGET];
                    }
                } else {
                    NSError * error = PA2MakeError(PowerAuthErrorCode_MissingActivation, @"Token for Watch cannot be obtained, because activation is no longer valid.");
                    response = [PA2WCSessionPacket packetWithError:error];
                }
                //
            } else {
                errorMessage = [NSString stringWithFormat:@"PowerAuthSDK+WatchSupport: Unsupported command '%@'. Target: %@", command, packet.target];
            }
        } else {
            errorMessage = [NSString stringWithFormat:@"PowerAuthSDK+WatchSupport: Received packet has invalid data. Target: %@", packet.target];
        }
    } while (false);
    
    if (errorMessage) {
        // Reply packet with error.
        response = [PA2WCSessionPacket packetWithError:PA2MakeError(PowerAuthErrorCode_WatchConnectivity, errorMessage)];
    }
    return response;
}

@end

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
