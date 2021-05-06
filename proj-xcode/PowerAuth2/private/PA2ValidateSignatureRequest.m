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

#import "PA2ValidateSignatureRequest.h"

@implementation PA2ValidateSignatureRequest
{
	NSDictionary<NSString*, NSObject*>* _content;
}

+ (instancetype) requestWithReason:(NSString *)reason
{
	return [[self alloc] initWithDictionary:@{ @"reason" : reason }];
}

+ (instancetype) requestWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
	return [[self alloc] initWithDictionary:dictionary];
}

- (instancetype) initWithDictionary:(nonnull NSDictionary<NSString*, NSObject*>*)dictionary
{
	self = [super init];
	if (self) {
		_content = dictionary;
	}
	return self;
}

- (NSDictionary<NSString*, NSObject*>*) toDictionary
{
	return _content;
}

@end
