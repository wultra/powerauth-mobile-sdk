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

#import "PA2EncryptedRequest.h"
#import "PA2PrivateMacros.h"

@import PowerAuthCore;

@implementation PA2EncryptedRequest

- (id) initWithCryptogram:(PowerAuthCoreEciesCryptogram*)cryptogram
{
	self = [super init];
	if (self) {
		_ephemeralPublicKey = cryptogram.keyBase64;
		_encryptedData = cryptogram.bodyBase64;
		_mac = cryptogram.macBase64;
		_nonce = cryptogram.nonceBase64;
	}
	return self;
}

- (NSDictionary*) toDictionary
{
	NSMutableDictionary * dict = [NSMutableDictionary dictionaryWithCapacity:3];
	if (_ephemeralPublicKey) {
		dict[@"ephemeralPublicKey"] = _ephemeralPublicKey;
	}
	if (_encryptedData) {
		dict[@"encryptedData"] = _encryptedData;
	}
	if (_mac) {
		dict[@"mac"] = _mac;
	}
	if (_nonce) {
		dict[@"nonce"] = _nonce;
	}
	return dict;
}

@end
