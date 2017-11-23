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

#import "PA2GetTokenResponse.h"
#import "PA2PrivateMacros.h"

@implementation PA2GetTokenResponse

- (instancetype)initWithDictionary:(NSDictionary *)dictionary
{
	self = [super init];
	if (self) {
		_tokenId 		= PA2ObjectAs(dictionary[@"tokenId"], NSString);
		_tokenSecret 	= PA2ObjectAs(dictionary[@"tokenSecret"], NSString);
	}
	return self;
}

- (NSDictionary *)toDictionary
{
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:3];
	if (_tokenId) {
		dictionary[@"tokenId"] = _tokenId;
	}
	if (_tokenSecret) {
		dictionary[@"tokenSecret"] = _tokenSecret;
	}
	return dictionary;
}

@end
