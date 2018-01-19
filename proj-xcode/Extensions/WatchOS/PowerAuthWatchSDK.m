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

#import "PowerAuthWatchSDK.h"
#import "PA2WatchSynchronizationService.h"
#import "PA2WatchRemoteTokenProvider.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2Keychain.h"

#import "PA2WCSessionPacket_ActivationStatus.h"

@implementation PowerAuthWatchSDK
{
	PowerAuthConfiguration * _configuration;
	PA2WatchRemoteTokenProvider * _remoteProvider;
}

#pragma mark - Init

- (id) initWithConfiguration:(PowerAuthConfiguration *)configuration
{
	self = [super init];
	if (self) {
		_configuration = [configuration copy];

		// Prepare remote token provider, which is using WatchConnectivity internally
		_remoteProvider = [[PA2WatchRemoteTokenProvider alloc] init];
		// Prepare keychain token store
		PA2KeychainConfiguration * keychainConfiguration = [PA2KeychainConfiguration sharedInstance];
		PA2Keychain * tokenStoreKeychain = [[PA2Keychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_TokenStore];
		// ..and finally, create token store
		PA2PrivateTokenKeychainStore * tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:_configuration
																									   keychain:tokenStoreKeychain
																								 statusProvider:self
																								 remoteProvider:_remoteProvider];
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

#pragma mark - Public methods

- (void) updateActivationStatusWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion
{
	
}

@end
