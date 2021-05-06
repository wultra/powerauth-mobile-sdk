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

#import "PA2VaultUnlockRequest.h"
#import "PA2PrivateMacros.h"

static NSString * _ReasonToString(PA2VaultUnlockReason reason)
{
	switch (reason) {
		case PA2VaultUnlockReason_ADD_BIOMETRY: 				return @"ADD_BIOMETRY";
		case PA2VaultUnlockReason_FETCH_ENCRYPTION_KEY:			return @"FETCH_ENCRYPTION_KEY";
		case PA2VaultUnlockReason_SIGN_WITH_DEVICE_PRIVATE_KEY:	return @"SIGN_WITH_DEVICE_PRIVATE_KEY";
		case PA2VaultUnlockReason_RECOVERY_CODE:				return @"RECOVERY_CODE";
		default:
			break;
	}
	// Will cause crash on request serialization. This is internal SDK error and should never happen.
	return nil;
}

@implementation PA2VaultUnlockRequest

- (id) initWithReason:(PA2VaultUnlockReason)reason
{
	self = [super init];
	if (self) {
		_reason = reason;
	}
	return self;
}

- (NSDictionary*) toDictionary
{
	return @{ @"reason" : _ReasonToString(_reason) };
}

@end
