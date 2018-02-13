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

#import "PA2KeychainConfiguration.h"

NSString *const PA2KeychainKey_Possession	= @"PA2KeychainKey_Possession";
NSString *const PA2Keychain_Initialized		= @"io.getlime.PowerAuthKeychain.Initialized";
NSString *const PA2Keychain_Status			= @"io.getlime.PowerAuthKeychain.StatusKeychain";
NSString *const PA2Keychain_Possession		= @"io.getlime.PowerAuthKeychain.PossessionKeychain";
NSString *const PA2Keychain_Biometry		= @"io.getlime.PowerAuthKeychain.BiometryKeychain";
NSString *const PA2Keychain_TokenStore		= @"io.getlime.PowerAuthKeychain.TokenStore";

@implementation PA2KeychainConfiguration

- (instancetype)init
{
	self = [super init];
	if (self) {
		// Initialize default value for keychain service keys
		_keychainInstanceName_Status		= PA2Keychain_Status;
		_keychainInstanceName_Possession	= PA2Keychain_Possession;
		_keychainInstanceName_Biometry		= PA2Keychain_Biometry;
		_keychainInstanceName_TokenStore	= PA2Keychain_TokenStore;
		
		// Initialize default values for keychain service record item keys
		_keychainKey_Possession	= PA2KeychainKey_Possession;
	}
	return self;
}

- (id)copyWithZone:(NSZone *)zone
{
	PA2KeychainConfiguration * c = [[self.class allocWithZone:zone] init];
	if (c) {
		c->_keychainAttribute_AccessGroup = _keychainAttribute_AccessGroup;
		c->_keychainAttribute_UserDefaultsSuiteName = _keychainAttribute_UserDefaultsSuiteName;
		c->_keychainInstanceName_Status = _keychainInstanceName_Status;
		c->_keychainInstanceName_Possession = _keychainInstanceName_Possession;
		c->_keychainInstanceName_Biometry = _keychainInstanceName_Biometry;
		c->_keychainInstanceName_TokenStore = _keychainInstanceName_TokenStore;
		c->_keychainKey_Possession = _keychainKey_Possession;
	}
	return c;
}

+ (PA2KeychainConfiguration *)sharedInstance
{
	static dispatch_once_t onceToken;
	static PA2KeychainConfiguration *inst;
	dispatch_once(&onceToken, ^{
		inst = [[PA2KeychainConfiguration alloc] init];
	});
	return inst;
}

@end
