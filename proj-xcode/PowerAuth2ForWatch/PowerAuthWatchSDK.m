/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import <PowerAuth2ForWatch/PowerAuthWatchSDK.h>
#import <PowerAuth2ForWatch/PowerAuthKeychain.h>
#import <PowerAuth2ForWatch/PowerAuthLog.h>

#import "PA2WatchSynchronizationService.h"
#import "PA2WatchRemoteTokenProvider.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateMacros.h"

#import "PA2WCSessionPacket_ActivationStatus.h"
#import "PowerAuthWCSessionManager+Private.h"

#pragma mark - Main Class -

@interface PowerAuthWatchSDK (TokenLock) <PA2TokenDataLock>
@end

@implementation PowerAuthWatchSDK
{
	PowerAuthConfiguration * _configuration;
    dispatch_semaphore_t _lockSemaphore;
	PA2WatchRemoteTokenProvider * _remoteProvider;
}

#pragma mark - Init

- (id) initWithConfiguration:(PowerAuthConfiguration *)configuration
{
	self = [super init];
	if (self) {
		_configuration = [configuration copy];
        _lockSemaphore = dispatch_semaphore_create(1);
        
		// Prepare remote token provider, which is using WatchConnectivity internally
		_remoteProvider = [[PA2WatchRemoteTokenProvider alloc] init];
		// Prepare keychain token store
		PowerAuthKeychainConfiguration * keychainConfiguration = [PowerAuthKeychainConfiguration sharedInstance];
		PowerAuthKeychain * tokenStoreKeychain = [[PowerAuthKeychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_TokenStore];
		// ..and finally, create token store
		PA2PrivateTokenKeychainStore * tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:_configuration
																									   keychain:tokenStoreKeychain
																								 statusProvider:self
																								 remoteProvider:_remoteProvider
                                                                                                       dataLock:self];
		tokenStore.allowInMemoryCache = NO;
		_tokenStore = tokenStore;
	}
	return self;
}


#pragma mark - Getters

- (PowerAuthConfiguration*) configuration
{
	return [_configuration copy];
}

- (NSString*) activationId
{
	return [[PA2WatchSynchronizationService sharedInstance] activationIdForSessionInstanceId:_configuration.instanceId];
}


#pragma mark - PA2SessionStatusProvider implementation

- (BOOL) canStartActivation;
{
	return NO;
}

- (BOOL) hasPendingActivation
{
	return NO;
}

- (BOOL) hasValidActivation
{
	return self.activationId != nil;
}

- (BOOL) hasPendingProtocolUpgrade
{
	return NO;
}

- (BOOL) hasProtocolUpgradeAvailable
{
	return NO;
}

#pragma mark - PA2TokenDataLock implementation

- (BOOL) lockTokenStore
{
    dispatch_semaphore_wait(_lockSemaphore, DISPATCH_TIME_FOREVER);
    return NO;
}

- (void) unlockTokenStore:(BOOL)contentModified
{
    dispatch_semaphore_signal(_lockSemaphore);
}

@end



#pragma mark - Status Synchronization -

@implementation PowerAuthWatchSDK (StatusSynchronization)

#pragma mark - Public methods

- (BOOL) updateActivationStatus
{
	PA2WCSessionPacket * request = [self requestStatusPacket];
	PowerAuthWCSessionManager * manager = [PowerAuthWCSessionManager sharedInstance];
	if (manager.validSession) {
		// The response will be handled in PA2WatchSynchronizationService as received userInfo message.
		[manager sendPacket:request];
		return YES;
	}
	return NO;
}

- (void) updateActivationStatusWithCompletion:(void(^ _Nonnull)(NSString * _Nullable activationId, NSError * _Nullable error))completion
{
	if (!completion) {
		PowerAuthLog(@"PowerAuthWatchSDK::updateActivationStatusWithCompletion: Missing completion block.");
		return;
	}
	PA2WCSessionPacket * request = [self requestStatusPacket];
	[[PowerAuthWCSessionManager sharedInstance] sendPacketWithResponse:request responseClass:[PA2WCSessionPacket_ActivationStatus class] completion:^(PA2WCSessionPacket *response, NSError *error) {
		NSString * activationId = nil;
		if (!error) {
			PA2WCSessionPacket_ActivationStatus * status = PA2ObjectAs(response.payload, PA2WCSessionPacket_ActivationStatus);
			BOOL invalidPacket = YES;
			if ([status validatePacketData]) {
				if ([status.command isEqualToString:PA2WCSessionPacket_CMD_SESSION_PUT]) {
					activationId = status.activationId;
					[[PA2WatchSynchronizationService sharedInstance] updateActivationId:activationId forSessionInstanceId:_configuration.instanceId];
					invalidPacket = NO;
				}
			}
			if (invalidPacket) {
				error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PowerAuthWatchSDK: Wrong status object received from iPhone.");
			}
		}
		dispatch_async(dispatch_get_main_queue(), ^{
			completion(activationId, error);
		});
	}];
}

#pragma mark - Private methods

- (PA2WCSessionPacket*) requestStatusPacket
{
	NSString * target = [PA2WCSessionPacket_SESSION_TARGET stringByAppendingString:_configuration.instanceId];
	PA2WCSessionPacket_ActivationStatus * status = [[PA2WCSessionPacket_ActivationStatus alloc] init];
	status.command = PA2WCSessionPacket_CMD_SESSION_GET;
	return [PA2WCSessionPacket packetWithData:status target:target];
}

@end
