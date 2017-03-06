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

#import "PA2PasswordUtil.h"

@implementation PA2PasswordUtil

+ (BOOL) isValid:(NSString*)password passwordType:(PasswordType)type {
	NSCharacterSet* notDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
	if ([password rangeOfCharacterFromSet:notDigits].location == NSNotFound) {
		return true;
	} else {
		return false;
	}
}

+ (BOOL) isWeak:(NSString*)password passwordType:(PasswordType)type {
	if (password.length < 4) {
		return true;
	}
	
	// "PIN Number Analysis" - http://www.datagenetics.com/blog/september32012/
	NSArray *weakList = @[@"1234", @"1111", @"0000", @"1212", @"7777",
						  @"1004", @"2000", @"4444", @"2222", @"6969",
						  @"9999", @"3333", @"5555", @"6666", @"1122",
						  @"1313", @"8888", @"4321", @"2001", @"1010"];
	if ([weakList containsObject:password]) {
		return true;
	}
	return false;
}

+ (BOOL) isNormal:(NSString*)password passwordType:(PasswordType)type {
	return ![self isWeak:password passwordType:type] && ![self isStrong:password passwordType:type];
}

+ (BOOL) isStrong:(NSString*)password passwordType:(PasswordType)type {
	return password.length >= 6 && ![self isWeak:password passwordType:type];
}

+ (PasswordStrength) evaluateStrength:(NSString*)password passwordType:(PasswordType)type {
	if (![self isValid:password passwordType:type]) {
		return PasswordStrength_INVALID;
	}
	if ([self isWeak:password passwordType:type]) {
		return PasswordStrength_WEAK;
	}
	if ([self isNormal:password passwordType:type]) {
		return PasswordStrength_NORMAL;
	}
	if (![self isStrong:password passwordType:type]) {
		return PasswordStrength_STRONG;
	}
	return PasswordStrength_INVALID;
}

@end
