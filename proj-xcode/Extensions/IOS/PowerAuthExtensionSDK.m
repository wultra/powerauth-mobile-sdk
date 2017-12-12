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

#import "PowerAuthExtensionSDK.h"
#import "PA2Keychain.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2SessionStatusDataReader.h"

@implementation PowerAuthExtensionSDK
{
	PowerAuthConfiguration * _configuration;
	PA2Keychain * _statusKeychain;
}

#pragma mark - Initialization

- (instancetype) initWithConfiguration:(PowerAuthConfiguration *)configuration
				 keychainConfiguration:(PA2KeychainConfiguration *)keychainConfiguration
{
	self = [super init];
	if (self) {
		_configuration = configuration;
		// Create status keychain
		_statusKeychain = [[PA2Keychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_Status
													  accessGroup:keychainConfiguration.keychainAttribute_AccessGroup];
		// Create token store keychain
		PA2Keychain * tokenStoreKeychain = [[PA2Keychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_TokenStore
																	   accessGroup:keychainConfiguration.keychainAttribute_AccessGroup];
		// ...and finally, create a token store
		_tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:configuration
																		 keychain:tokenStoreKeychain
																   statusProvider:self
																   remoteProvider:nil];
	}
	return self;
}

#pragma mark - Getters

- (PowerAuthConfiguration*) configuration
{
	return [_configuration copy];
}

#pragma mark - PA2SessionStatus implementation

- (BOOL) canStartActivation
{
	return NO;
}

- (BOOL) hasPendingActivation
{
	return NO;
}

- (BOOL) hasValidActivation
{
	if (NO == [[NSUserDefaults standardUserDefaults] boolForKey:PA2Keychain_Initialized]) {
		// Missing keychain initialization flag, stored in user defaults
		return NO;
	}
	// Retrieve & investigate data stored in keychain
	NSData *sessionData = [_statusKeychain dataForKey:_configuration.instanceId status:nil];
	return PA2SessionStatusDataReader_DataContainsActivation(sessionData);
}

@end
