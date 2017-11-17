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

#import "PA2EncryptedObject.h"
#import "PA2PrivateMacros.h"

@implementation PA2EncryptedObject

- (instancetype)initWithDictionary:(NSDictionary *)dictionary {
	self = [super init];
	if (self) {
		_sessionIndex		= PA2ObjectAs(dictionary[@"sessionIndex"], NSString);
		_adHocIndex			= PA2ObjectAs(dictionary[@"adHocIndex"], NSString);
		_macIndex			= PA2ObjectAs(dictionary[@"macIndex"], NSString);
		_nonce				= PA2ObjectAs(dictionary[@"nonce"], NSString);
		_mac				= PA2ObjectAs(dictionary[@"mac"], NSString);
		_encryptedData		= PA2ObjectAs(dictionary[@"encryptedData"], NSString);
	}
	return self;
}

- (NSDictionary *)toDictionary {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:6];
	if (_sessionIndex) {
		dictionary[@"sessionIndex"] = _sessionIndex;
	}
	if (_adHocIndex) {
		dictionary[@"adHocIndex"] = _adHocIndex;
	}
	if (_macIndex) {
		dictionary[@"macIndex"] = _macIndex;
	}
	if (_nonce) {
		dictionary[@"nonce"] = _nonce;
	}
	if (_mac) {
		dictionary[@"mac"] = _mac;
	}
	if (_encryptedData) {
		dictionary[@"encryptedData"] = _encryptedData;
	}
	return dictionary;
}

@end
