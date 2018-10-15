/**
 * Copyright 2016 Wultra s.r.o.
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

@implementation PowerAuthConfiguration

- (BOOL) validateConfiguration
{
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
		c->_disableAutomaticProtocolUpgrade = _disableAutomaticProtocolUpgrade;
	}
	return c;
}

@end
