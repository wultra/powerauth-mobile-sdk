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

#import "PA2EncryptorFactory.h"
#import "PA2Session.h"

@implementation PA2EncryptorFactory {
	__weak PA2Session *_session;
}

- (instancetype)initWithSession:(PA2Session*)session {
	self = [super init];
	if (self) {
		_session = session;
	}
	return self;
}

- (PA2RequestResponseNonPersonalizedEncryptor *)buildRequestResponseNonPersonalizedEncryptor {
	NSData *sessionIndex = [PA2Session generateSignatureUnlockKey];
	PA2Encryptor *encryptor = [_session nonpersonalizedEncryptorForSessionIndex:sessionIndex];
	return [[PA2RequestResponseNonPersonalizedEncryptor alloc] initWithEncryptor:encryptor];
}

@end
