/*
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

#import <PowerAuth2/PowerAuthActivation.h>
#import <PowerAuth2/PowerAuthLog.h>

#if defined(DEBUG)
#import "PA2ObjectSerialization.h"
#import "PA2CreateActivationRequest.h"
#endif

@implementation PowerAuthActivation

#pragma mark - Init & Copy

- (id) initWithIdentityAttributes:(NSDictionary*)identityAttributes
				   activationType:(NSString*)activationType
				   activationCode:(PowerAuthActivationCode*)activationCode
							 name:(NSString*)name
{
	self = [super init];
	if (self) {
		_identityAttributes = identityAttributes;
		_activationType = activationType;
		_activationCode = activationCode;
		_name = name;
	}
	return self;
}

- (id) copyWithZone:(NSZone *)zone
{
	PowerAuthActivation * copy = [[[self class] allocWithZone:zone] init];
	if (copy) {
		copy->_identityAttributes = _identityAttributes;
		copy->_activationType = _activationType;
		copy->_activationCode = _activationCode;
		copy->_name = _name;
		copy->_extras = _extras;
		copy->_customAttributes = _customAttributes;
		copy->_additionalActivationOtp = _additionalActivationOtp;
	}
	return copy;
}


#pragma mark - Static initializers

+ (instancetype) activationWithActivationCode:(NSString*)activationCode
										 name:(NSString*)name
{
	PowerAuthActivationCode * otp = [PowerAuthActivationCodeUtil parseFromActivationCode:activationCode];
	if (!otp) {
		PowerAuthLog(@"PowerAuthActivation: Invalid activation code '%@'", activationCode);
		return nil;
	}
	NSDictionary * identityAttributes = @{ @"code" : otp.activationCode };
	return [[PowerAuthActivation alloc] initWithIdentityAttributes:identityAttributes
													activationType:@"CODE"
													activationCode:otp
															  name:name];
}

+ (instancetype) activationWithIdentityAttributes:(NSDictionary<NSString*,NSString*>*)identityAttributes
											 name:(NSString*)name
{
	if (!identityAttributes || identityAttributes.count == 0) {
		PowerAuthLog(@"PowerAuthActivation: Missing identity attributes.");
		return nil;
	}
	return [[PowerAuthActivation alloc] initWithIdentityAttributes:identityAttributes
													activationType:@"CUSTOM"
													activationCode:nil
															  name:name];
}

+ (instancetype) activationWithRecoveryCode:(NSString*)recoveryCode
								recoveryPuk:(NSString*)recoveryPuk
									   name:(NSString*)name
{
	PowerAuthActivationCode * otp = [PowerAuthActivationCodeUtil parseFromRecoveryCode:recoveryCode];
	if (!otp) {
		PowerAuthLog(@"PowerAuthActivation: Invalid recovery code.");
		return nil;
	}
	if (![PowerAuthActivationCodeUtil validateRecoveryPuk:recoveryPuk]) {
		PowerAuthLog(@"PowerAuthActivation: Invalid recovery PUK.");
		return nil;
	}
	NSDictionary * identityAttributes = @{ @"recoveryCode" : otp.activationCode, @"puk" : recoveryPuk };
	return [[PowerAuthActivation alloc] initWithIdentityAttributes:identityAttributes
													activationType:@"RECOVERY"
													activationCode:nil
															  name:name];
}


#pragma mark - Customization

- (instancetype) withExtras:(NSString *)extras
{
	_extras = extras;
	return self;
}

- (instancetype) withCustomAttributes:(NSDictionary<NSString *,id> *)customAttributes
{
	_customAttributes = customAttributes;
	return self;
}

- (instancetype) withAdditionalActivationOtp:(NSString *)additionalActivationOtp
{
	_additionalActivationOtp = additionalActivationOtp;
	return self;
}

#pragma mark - Validation

- (BOOL) validate
{
	if (!_activationType || !_identityAttributes) {
		// May happen from swift, if object is constructed with default objc constructor.
		PowerAuthLog(@"PowerAuthActivation: Missing activation type or identity attributes.");
		return NO;
	}
	
	if (_additionalActivationOtp) {
		if (![_activationType isEqualToString:@"CODE"]) {
			PowerAuthLog(@"PowerAuthActivation: Only regular activation can be used with additional activation OTP.");
			return NO;
		}
		if (_additionalActivationOtp.length == 0) {
			PowerAuthLog(@"PowerAuthActivation: Empty additional activation OTP.");
			return NO;
		}
	}
#if defined(DEBUG)
	// For debug build, try to serialize the custom attributes.
	if (_customAttributes) {
		PA2CreateActivationRequest * request = [[PA2CreateActivationRequest alloc] init];
		request.customAttributes = _customAttributes;
		@try {
			NSData * serializedData = [PA2ObjectSerialization serializeObject:request];
			if (!serializedData) {
				PowerAuthLog(@"PowerAuthActivation: Failed to serialize customAttributes.");
				return NO;
			}
		} @catch (NSException *exception) {
			PowerAuthLog(@"PowerAuthActivation: Failed to serialize customAttributes: %@", exception.description);
			return NO;
		}
	}
#endif
	return YES;
}

#pragma mark - Debug

#if DEBUG
- (NSString*) description
{
	NSMutableString * optional = [NSMutableString string];
	if (_name) {
		[optional appendFormat:@", name=\"%@\"", _name];
	} else {
		[optional appendFormat:@", no-name"];
	}
	if (_additionalActivationOtp) {
		[optional appendFormat:@", otp=\"%@\"", _additionalActivationOtp];
	}
	if (_extras) {
		[optional appendFormat:@", extras=\"%@\"", _extras];
	}
	if (_customAttributes) {
		[optional appendFormat:@", customAttrs=%@", _customAttributes];
	}
	return [NSString stringWithFormat:@"<PowerAuthActivation type=\"%@\", identity=%@%@>", _activationType, _identityAttributes, optional];
}
#endif

@end
