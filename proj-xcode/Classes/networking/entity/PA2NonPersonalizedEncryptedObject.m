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

#import "PA2NonPersonalizedEncryptedObject.h"

@implementation PA2NonPersonalizedEncryptedObject

- (instancetype)initWithDictionary:(NSDictionary *)dictionary {
	self = [super initWithDictionary:dictionary];
	if (self) {
		_applicationKey		= [dictionary objectForKey:@"applicationKey"];
		_ephemeralPublicKey = [dictionary objectForKey:@"ephemeralPublicKey"];
	}
	return self;
}

- (NSDictionary *)toDictionary {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithDictionary:[super toDictionary]];
	if (_applicationKey) {
		[dictionary setObject:_applicationKey forKey:@"applicationKey"];
	}
	if (_ephemeralPublicKey) {
		[dictionary setObject:_ephemeralPublicKey forKey:@"ephemeralPublicKey"];
	}
	return dictionary;
}

@end
