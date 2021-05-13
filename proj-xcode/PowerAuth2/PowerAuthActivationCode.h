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

#import <PowerAuth2/PowerAuthMacros.h>

@class PowerAuthCoreOtp;

/**
 The `PowerAuthActivationCode` object contains parsed components from user-provided activation, or recovery
 code. You can use methods from `PowerAuthActivationCodeUtil` class to fill this object with valid data.
 */
@interface PowerAuthActivationCode : NSObject

/**
 If object is constructed from an activation code, then property contains just a code, without a signature part.
 If object is constructed from a recovery code, then property contains just a code, without an optional "R:" prefix.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * activationCode;
/**
 Signature calculated from activationCode. The value is typically optional for cases,
 when the user re-typed activation code manually.
 
 If object is constructed from a recovery code, then the activation signature part is always empty.
 */
@property (nullable, nonatomic, strong, readonly) NSString* activationSignature;

@end


/**
 The `PowerAuthActivationCodeUtil` class provides various set of methods for parsing and validating
 activation or recovery codes.
 
 Current format:
 ------------------
 code without signature:	CCCCC-CCCCC-CCCCC-CCCCC
 code with signature:		CCCCC-CCCCC-CCCCC-CCCCC#BASE64_STRING_WITH_SIGNATURE
 
 recovery code:				CCCCC-CCCCC-CCCCC-CCCCC
 recovery code from QR:		R:CCCCC-CCCCC-CCCCC-CCCCC
 
 recovery PUK:				DDDDDDDDDD
 
 - Where the 'C' is Base32 sequence of characters, fully decodable into the sequence of bytes.
   The validator then compares CRC-16 checksum calculated for the first 10 bytes and compares
   it to last two bytes (in big endian order).
 
 - Where the 'D' is digit (0 - 9)
 
 As you can see, both activation and recovery codes, shares the same basic principle (like CRC16
 checksum). That's why parser returns the same `PowerAuthActivationCode` object for both scenarios.
 */
@interface PowerAuthActivationCodeUtil : NSObject

#pragma mark - Validations

/**
 Returns YES if |utfCodepoint| is a valid character allowed in the activation or recovery code.
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

/**
 Returns YES if |recoveryCode| is a valid recovery code. You can use this method to validate
 a whole user-typed recovery code at once. The input code may contain "R:" prefix, if code is
 scanned from QR code.
 */
+ (BOOL) validateRecoveryCode:(nonnull NSString*)recoveryCode;

/**
 Returns true if |recoveryPuk| appears to be valid. You can use this method to validate
 a whole user-typed recovery PUK at once. In current version, only 10 digits long string is considered
 as a valid PUK.
 */
+ (BOOL) validateRecoveryPuk:(nonnull NSString*)recoveryPuk;

#pragma mark - Parser

/**
 Parses an input |activationCode| (which may or may not contain an optional signature) and returns PowerAuthActivationCode
 object filled with valid data. The method doesn't perform an auto-correction, so the provided code must be valid.
 
 Returns PowerAuthActivationCode object if code is valid, or nil.
 */
+ (nullable PowerAuthActivationCode*) parseFromActivationCode:(nonnull NSString*)activationCode;

/**
 Parses an input |recoveryCode| (which may or may not contain an optional "R:" prefix) and returns `PowerAuthActivationCode`
 object filled with valid data. The method doesn't perform an auto-correction, so the provided code must be valid.
 
 Returns PowerAuthActivationCode object if code is valid, or nil.
 */
+ (nullable PowerAuthActivationCode*) parseFromRecoveryCode:(nonnull NSString*)recoveryCode;

@end
