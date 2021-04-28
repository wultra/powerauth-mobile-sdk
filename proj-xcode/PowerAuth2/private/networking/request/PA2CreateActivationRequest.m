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

#import "PA2CreateActivationRequest.h"
#import "PA2EncryptedRequest.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateActivationRequest

- (NSDictionary*) toDictionary
{
    NSMutableDictionary * dictionary = [NSMutableDictionary dictionaryWithCapacity:4];
	if (_activationType) {
		dictionary[@"type"] = _activationType;
	}
	if (_identityAttributes) {
		dictionary[@"identityAttributes"] = _identityAttributes;
	}
	if (_customAttributes) {
		dictionary[@"customAttributes"] = _customAttributes;
	}
	NSDictionary * activationData = [_activationData toDictionary];
	if (activationData) {
		dictionary[@"activationData"] = activationData;
	}
    return dictionary;
}

@end
