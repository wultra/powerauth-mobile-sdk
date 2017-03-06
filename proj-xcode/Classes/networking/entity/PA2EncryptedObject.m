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

@implementation PA2EncryptedObject

- (instancetype)initWithDictionary:(NSDictionary *)dictionary {
	self = [super init];
	if (self) {
		_sessionIndex		= [dictionary objectForKey:@"sessionIndex"];
		_adHocIndex			= [dictionary objectForKey:@"adHocIndex"];
		_macIndex			= [dictionary objectForKey:@"macIndex"];
		_nonce				= [dictionary objectForKey:@"nonce"];
		_mac				= [dictionary objectForKey:@"mac"];
		_encryptedData		= [dictionary objectForKey:@"encryptedData"];
	}
	return self;
}

- (NSDictionary *)toDictionary {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	if (_sessionIndex) {
		[dictionary setObject:_sessionIndex forKey:@"sessionIndex"];
	}
	if (_adHocIndex) {
		[dictionary setObject:_adHocIndex forKey:@"adHocIndex"];
	}
	if (_macIndex) {
		[dictionary setObject:_macIndex forKey:@"macIndex"];
	}
	if (_nonce) {
		[dictionary setObject:_nonce forKey:@"nonce"];
	}
	if (_mac) {
		[dictionary setObject:_mac forKey:@"mac"];
	}
	if (_encryptedData) {
		[dictionary setObject:_encryptedData forKey:@"encryptedData"];
	}
	return dictionary;
}

@end
