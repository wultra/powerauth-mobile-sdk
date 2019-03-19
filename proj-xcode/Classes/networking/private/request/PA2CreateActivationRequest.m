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

#import "PA2CreateActivationRequest.h"
#import "PA2EncryptedRequest.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateActivationRequest

- (NSDictionary*) toDictionary
{
    NSMutableDictionary * dictionary = [NSMutableDictionary dictionaryWithCapacity:3];
	if (_activationType) {
		dictionary[@"type"] = _activationType;
	}
	if (_identityAttributes) {
		dictionary[@"identityAttributes"] = _identityAttributes;
	}
	NSDictionary * activationData = [_activationData toDictionary];
	if (activationData) {
		dictionary[@"activationData"] = activationData;
	}
    return dictionary;
}

+ (instancetype) standardActivationWithCode:(NSString*)activationCode
{
	PA2CreateActivationRequest * obj = [[PA2CreateActivationRequest alloc] init];
	if (obj) {
		obj->_activationType = @"CODE";
		obj->_identityAttributes = @{ @"code" : activationCode };
	}
	return obj;
}

+ (instancetype) customActivationWithIdentityAttributes:(NSDictionary<NSString*, NSString*>*)attributes
{
	PA2CreateActivationRequest * obj = [[PA2CreateActivationRequest alloc] init];
	if (obj) {
		obj->_activationType = @"CUSTOM";
		obj->_identityAttributes = attributes;
	}
	return obj;
}

+ (instancetype) recoveryActivationWithCode:(NSString*)recoveryCode puk:(NSString*)puk
{
	PA2CreateActivationRequest * obj = [[PA2CreateActivationRequest alloc] init];
	if (obj) {
		obj->_activationType = @"RECOVERY";
		obj->_identityAttributes = @{ @"recoveryCode" : recoveryCode, @"puk" : puk };
	}
	return obj;
}

@end
