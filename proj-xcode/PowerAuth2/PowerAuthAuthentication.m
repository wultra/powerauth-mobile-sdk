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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2/PowerAuthAuthentication.h>
#import <PowerAuth2/PowerAuthKeychainAuthentication.h>

@implementation PowerAuthAuthentication

- (id)copyWithZone:(NSZone *)zone
{
	PowerAuthAuthentication * copy = [[[self class] allocWithZone:zone] init];
	if (copy) {
		copy->_usePossession = _usePossession;
		copy->_useBiometry = _useBiometry;
		copy->_usePassword = _usePassword;
		copy->_biometryPrompt = _biometryPrompt;
		copy->_overridenPossessionKey = _overridenPossessionKey;
		copy->_overridenBiometryKey = _overridenBiometryKey;
#if PA2_HAS_LACONTEXT == 1
		copy->_biometryContext = _biometryContext;
#endif
	}
	return copy;
}

- (PowerAuthKeychainAuthentication*) keychainAuthentication
{
#if PA2_HAS_LACONTEXT == 1
	if (_biometryContext) {
		return [[PowerAuthKeychainAuthentication alloc] initWithContext:_biometryContext];
	}
#endif // PA2_HAS_LACONTEXT
	if (_biometryPrompt) {
		return [[PowerAuthKeychainAuthentication alloc] initWithPrompt:_biometryPrompt];
	}
	return nil;
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
	if (_biometryPrompt) {
		[info addObject:@"+prompt"];
	}
#if PA2_HAS_LACONTEXT == 1
	if (_biometryContext) {
		[info addObject:@"+context"];
	}
#endif
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


@implementation PowerAuthAuthentication (EasyAccessors)

+ (PowerAuthAuthentication*) possession
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	return auth;
}

+ (PowerAuthAuthentication*) possessionWithBiometry
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = YES;
	return auth;
}

+ (PowerAuthAuthentication*) possessionWithBiometryWithPrompt:(NSString *)biometryPrompt
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = YES;
	auth.biometryPrompt = biometryPrompt;
	return auth;
}

+ (PowerAuthAuthentication*) possessionWithPassword:(NSString *)password
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.usePassword = password;
	return auth;
}

#if PA2_HAS_LACONTEXT == 1
+ (PowerAuthAuthentication*) possessionWithBiometryWithContext:(LAContext*)context
{
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = YES;
	auth.biometryContext = context;
	return auth;
}
#endif // PA2_HAS_LACONTEXT

@end
