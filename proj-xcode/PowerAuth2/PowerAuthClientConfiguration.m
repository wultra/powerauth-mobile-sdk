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

#import <PowerAuth2/PowerAuthClientConfiguration.h>

@implementation PowerAuthClientConfiguration

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
	PowerAuthClientConfiguration * c = [[self.class allocWithZone:zone] init];
	if (c) {
		c->_defaultRequestTimeout = _defaultRequestTimeout;
		c->_sslValidationStrategy = _sslValidationStrategy;
		c->_requestInterceptors = [_requestInterceptors copyWithZone:zone];
	}
	return c;
}

+ (PowerAuthClientConfiguration *) sharedInstance
{
	static dispatch_once_t onceToken;
	static PowerAuthClientConfiguration *inst;
	dispatch_once(&onceToken, ^{
		inst = [[PowerAuthClientConfiguration alloc] init];
	});
	return inst;
}

@end
