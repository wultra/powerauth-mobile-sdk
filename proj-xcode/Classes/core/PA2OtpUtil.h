/**
 * Copyright 2016-2017 Wultra s.r.o.
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

/**
 The `PA2Otp` object contains parsed components from user-provided activation
 code. You can use methods from `PA2OtpUtil` class to fill this object with valid data.
 */
@interface PA2Otp : NSObject

/**
 Activation code, without signature part.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * activationCode;
/**
 Signature calculated from activationIdShort and activationOtp.
 The value is typically optional for cases, when the user re-typed activation ode
 manually.
 */
@property (nullable, nonatomic, strong, readonly) NSString* activationSignature;

@end


/** 
 The `PA2OtpUtil` class provides various set of methods for parsing and validating activation codes.
 
 Current format:
 ------------------
 code without signature:	CCCCC-CCCCC-CCCCC-CCCCC
 code with signature:		CCCCC-CCCCC-CCCCC-CCCCC#BASE64_STRING_WITH_SIGNATURE
 
 Where the 'C' is Base32 sequence of characters, fully decodable into the sequence of bytes.
 The validator then compares CRC-16 checksum calculated for the first 10 bytes and compares
 it to last two bytes (in big endian order).
 */
@interface PA2OtpUtil : NSObject

#pragma mark - Validations

/**
 Returns YES if |utfCodepoint| is a valid character allowed in the activation code.
 The method strictly checks whether the character is from [A-Z2-7] characters range.
 */
+ (BOOL) validateTypedCharacter:(UInt32)utfCodepoint;

/**
 Validates an input |utfCodepoint| and returns '\0' (NUL) if it's not valid or cannot be corrected.
 The non-NUL returned value contains the same input character, or the corrected one.
 You can use this method for validation & auto-correction of just typed characters.
 
 The function performs following auto-corections:
 - lowercase characters are corrected to uppercase (e.g. 'a' will be corrected to 'A')
 - '0' is corrected to 'O'
 - '1' is corrected to 'I'
 */
+ (UInt32) validateAndCorrectTypedCharacter:(UInt32)utfCodepoint;

/**
 Returns YES if |activationCode| is a valid activation code. The input code must not contain a signature part.
 You can use this method to validate a whole user-typed activation code at once.
 */
+ (BOOL) validateActivationCode:(nonnull NSString*)activationCode;

#pragma mark - Parser

/**
 Parses an input |activationCode| (which may or may not contain an optional signature) and returns PA2Otp 
 object filled with valid data. The method doesn't perform an auto-correction, so the provided code must be valid.
 
 Returns PA2Otp object if code is valid, or nil.
 */
+ (nullable PA2Otp*) parseFromActivationCode:(nonnull NSString*)activationCode;

@end
