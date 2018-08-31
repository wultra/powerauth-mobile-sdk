/**
 * Copyright 2017 Wultra s.r.o.
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

#import "PA2DirectCreateActivationRequest.h"

@implementation PA2DirectCreateActivationRequest

- (instancetype)initWithDictionary:(NSDictionary *)dictionary {
	self = [super init];
	if (self) {
		_identity           = [dictionary objectForKey:@"_identity"];
		_customAttributes   = [dictionary objectForKey:@"_customAttributes"];
		NSDictionary *powerAuthDict = [dictionary objectForKey:@"_powerauth"];
		if (powerAuthDict) {
			_powerauth      = [[PA2CreateActivationRequest alloc] initWithDictionary:powerAuthDict];
		}
	}
	return self;
}

- (NSDictionary *)toDictionary {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	if (_identity) {
		[dictionary setObject:_identity forKey:@"identity"];
	}
	if (_customAttributes) {
		[dictionary setObject:_customAttributes forKey:@"customAttributes"];
	}
	if (_powerauth) {
		[dictionary setObject:[_powerauth toDictionary] forKey:@"powerauth"];
	}
	return dictionary;

}

@end
