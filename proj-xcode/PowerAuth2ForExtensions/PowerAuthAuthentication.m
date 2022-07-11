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

#import <PowerAuth2ForExtensions/PowerAuthAuthentication.h>
#import <PowerAuth2ForExtensions/PowerAuthKeychainAuthentication.h>
#import <PowerAuth2ForExtensions/PowerAuthLog.h>
#import "PowerAuthAuthentication+Private.h"

@implementation PowerAuthAuthentication
{
	NSInteger _objectUsage;
}

#define AUTH_FOR_COMMIT			1
#define AUTH_FOR_SIGN			2

- (id) initWithObjectUsage:(NSInteger)objectUsage
				  password:(NSString*)password
				  biometry:(BOOL)biometry
			biometryPrompt:(NSString*)biometryPrompt
		   biometryContext:(id)biometryContext
	   customPossessionKey:(NSData*)customPossessionKey
		 customBiometryKey:(NSData*)customBiometryKey
{
	self = [super init];
	if (self) {
		_objectUsage = objectUsage;
		_usePossession = YES;
		_usePassword = password;
		_useBiometry = biometry;
		_biometryPrompt = biometryPrompt;
		_biometryContext = biometryContext;
		_overridenPossessionKey = customPossessionKey;
		_overridenBiometryKey = customBiometryKey;
	}
	return self;
}

- (id) copyWithZone:(NSZone *)zone
{
	PowerAuthAuthentication * copy = [[[self class] allocWithZone:zone] init];
	if (copy) {
		copy->_objectUsage = _objectUsage;
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

- (PowerAuthKeychainAuthentication *) keychainAuthentication
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
	NSString * usage_str;
	if (_objectUsage == AUTH_FOR_SIGN) {
		usage_str = @"for sign";
	} else if (_objectUsage == AUTH_FOR_COMMIT) {
		usage_str = @"for commit";
	} else {
		usage_str = @"legacy";
	}
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
	return [NSString stringWithFormat:@"<PowerAuthAuthentication %@: %@%@>", usage_str, factors_str, info_str];
}
#endif

@end


@implementation PowerAuthAuthentication (EasyAccessors)

// MARK: - Commit, Possession + Knowledge

#if PA2_HAS_CORE_MODULE

+ (PowerAuthAuthentication*) commitWithPassword:(NSString*)password
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_COMMIT
													   password:password
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication*) commitWithPassword:(NSString*)password
							customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_COMMIT
													   password:password
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:nil];
}

// MARK: Commit, Possession + Knowledge + Biometry

+ (PowerAuthAuthentication*) commitWithPasswordAndBiometry:(NSString*)password
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_COMMIT
													   password:password
													   biometry:YES
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication*) commitWithPasswordAndBiometry:(NSString*)password
										 customBiometryKey:(NSData*)customBiometryKey
									   customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_COMMIT
													   password:password
													   biometry:YES
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:customBiometryKey];
}

#endif // PA2_HAS_CORE_MODULE


// MARK: - Signing, Possession only

+ (PowerAuthAuthentication *) possession
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithCustomPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:nil];
}

// MARK: Signing, Possession + Biometry

+ (PowerAuthAuthentication *) possessionWithBiometry
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:YES
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:YES
												 biometryPrompt:biometryPrompt
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
									   customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:YES
												 biometryPrompt:biometryPrompt
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryWithCustomBiometryKey:(NSData*)customBiometryKey
													  customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:YES
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:customBiometryKey];
}

#if PA2_HAS_LACONTEXT == 1
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext *)context
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:context
											customPossessionKey:nil
											  customBiometryKey:nil];
}
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext*)context
										customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:nil
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:context
											customPossessionKey:customPossessionKey
											  customBiometryKey:nil];
}
#endif // PA2_HAS_LACONTEXT

// MARK: Signing, Possession + Knowledge

+ (PowerAuthAuthentication *) possessionWithPassword:(NSString *)password
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:password
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:nil
											  customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithKnowledge:(NSString*)password
								  customPossessionKey:(NSData*)customPossessionKey
{
	return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
													   password:password
													   biometry:NO
												 biometryPrompt:nil
												biometryContext:nil
											customPossessionKey:customPossessionKey
											  customBiometryKey:nil];
}

#pragma mark - Deprecated

// PA2_DEPRECATED(1.7.0)
+ (PowerAuthAuthentication *) possessionWithBiometryWithPrompt:(NSString *)biometryPrompt
{
	return [self possessionWithBiometryPrompt:biometryPrompt];
}
// PA2_DEPRECATED(1.7.0)
+ (PowerAuthAuthentication *) possessionWithPasswordDeprecated:(NSString*)password
{
	return [self possessionWithPassword:password];
}
@end


@implementation PowerAuthAuthentication (Private)

- (NSInteger) signatureFactorMask
{
	NSUInteger result = 0;
	if (_usePossession) result |= 1;
	if (_usePassword)   result |= 2;
	if (_useBiometry)   result |= 4;
	return result;
}

- (BOOL) validateUsage:(BOOL)forCommit
{
	if (_objectUsage == 0) {
		PowerAuthLog(@"WARNING: Using PowerAuthAuthentication object created with legacy constructor.");
		return NO;
	}
	if (forCommit != (_objectUsage == AUTH_FOR_COMMIT)) {
		if (forCommit) {
			PowerAuthLog(@"WARNING: Using PowerAuthAuthentication object for a different purpose. The object for activation commit is expected.");
		} else {
			PowerAuthLog(@"WARNING: Using PowerAuthAuthentication object for a different purpose. The object for signature calculation is expected.");
		}
		return NO;
	}
	return YES;
}

@end
