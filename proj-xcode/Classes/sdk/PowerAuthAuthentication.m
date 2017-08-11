/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import "PowerAuthAuthentication.h"

@implementation PowerAuthAuthentication

- (id)copyWithZone:(NSZone *)zone
{
	PowerAuthAuthentication * copy = [[[self class] allocWithZone:zone] init];
	if (copy) {
		copy->_usePossession = _usePossession;
		copy->_useBiometry = _useBiometry;
		copy->_usePassword = _usePassword;
		copy->_touchIdPrompt = _touchIdPrompt;
		copy->_overridenPossessionKey = _overridenPossessionKey;
		copy->_overridenBiometryKey = _overridenBiometryKey;
	}
	return copy;
}

#if DEBUG
- (NSString*) description
{
	NSMutableArray * factors = [NSMutableArray arrayWithCapacity:3];
	if (_usePossession) {
		[factors addObject:@"possession"];
	}
	if (_usePassword) {
		[factors addObject:@"knowledge"];
	}
	if (_useBiometry) {
		[factors addObject:@"biometry"];
	}
	NSString * factors_str = [factors componentsJoinedByString:@"_"];
	NSMutableArray * info = [NSMutableArray array];
	if (_touchIdPrompt) {
		[info addObject:@"+prompt"];
	}
	if (_overridenBiometryKey) {
		[info addObject:@"+extBK"];
	}
	if (_overridenPossessionKey) {
		[info addObject:@"+extPK"];
	}
	NSString * info_str = info.count == 0 ? @"" : [@", " stringByAppendingString:[info componentsJoinedByString:@" "]];
	return [NSString stringWithFormat:@"<PowerAuthAuthentication factors: %@%@>", factors_str, info_str];
}
#endif

@end
