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

#import <PowerAuth2/PowerAuthToken+WatchSupport.h>
#import <PowerAuth2/PowerAuthConfiguration.h>
#import <PowerAuth2/PowerAuthLog.h>

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

#import "PA2PrivateTokenInterfaces.h"
#import "PowerAuthWCSessionManager+Private.h"
#import "PA2WCSessionPacket_TokenData.h"
#import "PA2WCSessionPacket_Success.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateMacros.h"

@implementation PowerAuthToken (WatchSupport)

#pragma mark - Upload token

- (PA2WCSessionPacket*) prepareTokenDataPacketForWatch
{
	PA2PrivateTokenKeychainStore * typedStore = PA2ObjectAs(self.tokenStore, PA2PrivateTokenKeychainStore);
	NSString * targetIdentifier = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:typedStore.configuration.instanceId];
	
	PA2WCSessionPacket_TokenData * packetData = [[PA2WCSessionPacket_TokenData alloc] init];
	packetData.command = PA2WCSessionPacket_CMD_TOKEN_PUT;
	packetData.tokenName = self.tokenName;
	packetData.tokenData = [self.privateTokenData serializedData];
	return [PA2WCSessionPacket packetWithData:packetData target:targetIdentifier];
}


- (BOOL) sendToWatch
{
	if (@available(iOS 9, *)) {
		if ([self.tokenStore canRequestForAccessToken]) {
			PowerAuthWCSessionManager * manager = [PowerAuthWCSessionManager sharedInstance];
			if (manager.validSession) {
				[manager sendPacket:[self prepareTokenDataPacketForWatch]];
				return YES;
			}
			PowerAuthLog(@"PowerAuthToken: WCSession is not ready for message sending.");
		} else {
			PowerAuthLog(@"PowerAuthToken: Cannot send token to watch, because token store has no longer a valid activation.");
		}
	} else {
		PowerAuthLog(@"PowerAuthToken: WCSession is not supported on older iOS versions.");
	}
	return NO;
}


- (void) sendToWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion
{
	if (![self.tokenStore canRequestForAccessToken]) {
		if (completion) {
			dispatch_async(dispatch_get_main_queue(), ^{
				completion(PA2MakeError(PowerAuthErrorCode_MissingActivation, @"Cannot send token to watch, because token store has no longer a valid activation."));
			});
		}
		return;
	}
	PA2WCSessionPacket * packet = [self prepareTokenDataPacketForWatch];
	[[PowerAuthWCSessionManager sharedInstance] sendPacketWithResponse:packet responseClass:[PA2WCSessionPacket_Success class] completion:^(PA2WCSessionPacket *response, NSError *error) {
		if (completion) {
			dispatch_async(dispatch_get_main_queue(), ^{
				completion(error);
			});
		}
	}];
}


#pragma mark - Remove token

- (PA2WCSessionPacket*) prepareTokenRemovePacketForWatch
{
	PA2PrivateTokenKeychainStore * typedStore = PA2ObjectAs(self.tokenStore, PA2PrivateTokenKeychainStore);
	NSString * targetIdentifier = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:typedStore.configuration.instanceId];
	
	PA2WCSessionPacket_TokenData * packetData = [[PA2WCSessionPacket_TokenData alloc] init];
	packetData.command = PA2WCSessionPacket_CMD_TOKEN_REMOVE;
	packetData.tokenName = self.tokenName;
	return [PA2WCSessionPacket packetWithData:packetData target:targetIdentifier];
}


- (BOOL) removeFromWatch
{
	if (@available(iOS 9, *)) {
		PowerAuthWCSessionManager * manager = [PowerAuthWCSessionManager sharedInstance];
		if (manager.validSession) {
			[manager sendPacket:[self prepareTokenRemovePacketForWatch]];
			return YES;
		}
	}
	PowerAuthLog(@"PowerAuthToken: WCSession is not ready for message sending.");
	return NO;
}


- (void) removeFromWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion
{
	if (@available(iOS 9, *)) {
		PA2WCSessionPacket * packet = [self prepareTokenRemovePacketForWatch];
		[[PowerAuthWCSessionManager sharedInstance] sendPacketWithResponse:packet responseClass:[PA2WCSessionPacket_Success class] completion:^(PA2WCSessionPacket *response, NSError *error) {
			if (completion) {
				dispatch_async(dispatch_get_main_queue(), ^{
					completion(error);
				});
			}
		}];
	} else {
		if (completion) {
			completion(PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"Not supported on older iOS versions"));
		}
	}
}

@end

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
