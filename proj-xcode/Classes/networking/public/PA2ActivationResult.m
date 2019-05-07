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

#import "PA2ActivationResult.h"

@implementation PA2ActivationResult

#ifdef DEBUG
- (NSString*) description
{
	NSString * fingerprint = _activationFingerprint ? _activationFingerprint : @"<null>";
	NSString * rc = _activationRecovery ? [@", recovery=" stringByAppendingString:[_activationRecovery description]] : @"";
	NSString * attrs = _customAttributes ? [@", attributes=" stringByAppendingString:[_customAttributes description]] : @"";
	return [NSString stringWithFormat:@"<PA2ActivationResult fingerprint=%@%@%@>", fingerprint, rc,attrs];
}
#endif

@end
