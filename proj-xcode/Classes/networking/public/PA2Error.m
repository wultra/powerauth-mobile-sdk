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

#import "PA2Error+Decodable.h"
#import "PA2PrivateMacros.h"

@implementation PA2Error

#ifdef DEBUG
- (NSString*) description
{
	return [NSString stringWithFormat:@"<PA2Error code=%@, message=%@>", _code ? _code : @"<null>", _message ? _message : @"<null>"];
}
#endif

@end

@implementation PA2Error (Decodable)

- (instancetype) initWithDictionary:(NSDictionary *)dictionary
{
	self = [super init];
	if (self) {
		_code		= PA2ObjectAs(dictionary[@"code"], NSString);
		_message    = PA2ObjectAs(dictionary[@"message"], NSString);
	}
	return self;
}

@end
