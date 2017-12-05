/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import "PowerAuthConfiguration.h"

@implementation PA2KeychainConfiguration

- (instancetype)init {
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
 
+ (PA2KeychainConfiguration *)sharedInstance {
	static dispatch_once_t onceToken;
	static PA2KeychainConfiguration *inst;
	dispatch_once(&onceToken, ^{
		inst = [[PA2KeychainConfiguration alloc] init];
	});
	return inst;
}

@end

@implementation PA2ClientConfiguration

- (instancetype)init {
	self = [super init];
	if (self) {
		self.defaultRequestTimeout = 20.0;
	}
	return self;
}

+ (PA2ClientConfiguration *)sharedInstance {
	static dispatch_once_t onceToken;
	static PA2ClientConfiguration *inst;
	dispatch_once(&onceToken, ^{
		inst = [[PA2ClientConfiguration alloc] init];
	});
	return inst;
}

@end

#pragma mark - Main PowerAuthConfiguration class

@implementation PowerAuthConfiguration

- (BOOL) validateConfiguration {
	BOOL result = YES;
	result = result && (self.instanceId != nil);
	result = result && (self.appKey != nil);
	result = result && (self.appSecret != nil);
	result = result && (self.masterServerPublicKey != nil);
	result = result && (self.baseEndpointUrl != nil);
	return result;
}

- (id)copyWithZone:(NSZone *)zone
{
	PowerAuthConfiguration * c = [[self.class allocWithZone:zone] init];
	if (c) {
		c->_instanceId = _instanceId;
		c->_baseEndpointUrl = _baseEndpointUrl;
		c->_appKey = _appKey;
		c->_appSecret = _appSecret;
		c->_masterServerPublicKey = _masterServerPublicKey;
		c->_keychainKey_Biometry = _keychainKey_Biometry;
		c->_externalEncryptionKey = _externalEncryptionKey;
	}
	return c;
}

@end
