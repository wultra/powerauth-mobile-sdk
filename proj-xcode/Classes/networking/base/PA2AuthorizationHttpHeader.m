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

#import "PA2AuthorizationHttpHeader.h"

@implementation PA2AuthorizationHttpHeader

- (instancetype)initWithKey:(NSString*)key value:(NSString*)value
{
	self = [super init];
	if (self) {
		_key = key;
		_value = value;
	}
	return self;
}

+ (PA2AuthorizationHttpHeader*) authorizationHeaderWithValue:(NSString *)value
{
	return !value ? nil : [[self alloc] initWithKey:@"X-PowerAuth-Authorization" value:value];
}

+ (PA2AuthorizationHttpHeader*) tokenHeaderWithValue:(NSString *)value
{
	return !value ? nil : [[self alloc] initWithKey:@"X-PowerAuth-Token" value:value];
}

@end
