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

#import "PA2Macros.h"

/** Indicator of a password strength.
 */
typedef NS_ENUM(int, PasswordStrength) {
	PasswordStrength_INVALID = 0,	// Password cannot be evaluated (i.e., invalid PIN).
	PasswordStrength_WEAK = 1,		// Weak password - indicate password weakness
	PasswordStrength_NORMAL = 2,	// Normal password - this should be shown as OK
	PasswordStrength_STRONG = 3		// String password - this should be rewarded
};

/** Password type
 */
typedef NS_ENUM(int, PasswordType) {
	PasswordType_PIN = 0		// PIN - password made of 4+ digits ([0-9]{4,})
//	PasswordType_PASSWORD = 1	// Freeform password, with any characters
};

/** Class used for validating passwords.
 
 This class will be removed in some future version of SDK. You can migrate your code to
 Wultra Passphrase Meter - https://github.com/wultra/passphrase-meter library, which
 provides a better PIN and password strength evaluation.
 */
@interface PA2PasswordUtil : NSObject

/** Evaluate provided password strength using logic that depends on a password type.
 
 @param password Password to be evaluated.
 @param type Type of the password (for example, numeric PIN code).
 @return Estimated password strength.
 */
+ (PasswordStrength) evaluateStrength:(NSString*)password passwordType:(PasswordType)type PA2_DEPRECATED(1.1.0);

@end
