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

#import "PA2ClientConfiguration.h"

@implementation PA2ClientConfiguration

- (instancetype)init
{
	self = [super init];
	if (self) {
		self.defaultRequestTimeout = 20.0;
	}
	return self;
}

- (id)copyWithZone:(NSZone *)zone
{
	PA2ClientConfiguration * c = [[self.class allocWithZone:zone] init];
	if (c) {
		c->_defaultRequestTimeout = _defaultRequestTimeout;
		c->_sslValidationStrategy = _sslValidationStrategy;
	}
	return c;
}

+ (PA2ClientConfiguration *) sharedInstance
{
	static dispatch_once_t onceToken;
	static PA2ClientConfiguration *inst;
	dispatch_once(&onceToken, ^{
		inst = [[PA2ClientConfiguration alloc] init];
	});
	return inst;
}

@end
