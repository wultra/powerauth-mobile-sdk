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

#import "PowerAuthActivationCode+Private.h"

@implementation PowerAuthActivationCode
{
    PowerAuthCoreOtp * _coreActivationCode;
}

- (id) initWithCoreActivationCode:(PowerAuthCoreOtp*)otp
{
    self = [super init];
    if (self) {
        _coreActivationCode = otp;
    }
    return self;
}

- (PowerAuthCoreOtp*) coreActivationCode
{
    return _coreActivationCode;
}

- (NSString*) activationCode
{
    return _coreActivationCode.activationCode;
}

- (NSString*) activationSignature
{
    return _coreActivationCode.activationSignature;
}

@end



@implementation PowerAuthActivationCodeUtil

+ (BOOL) validateTypedCharacter:(UInt32)utfCodepoint
{
    return [PowerAuthCoreOtpUtil validateTypedCharacter:utfCodepoint];
}

+ (UInt32) validateAndCorrectTypedCharacter:(UInt32)utfCodepoint
{
    return [PowerAuthCoreOtpUtil validateAndCorrectTypedCharacter:utfCodepoint];
}

+ (BOOL) validateActivationCode:(NSString*)activationCode
{
    return [PowerAuthCoreOtpUtil validateActivationCode:activationCode];
}

+ (BOOL) validateRecoveryCode:(NSString*)recoveryCode
{
    return [PowerAuthCoreOtpUtil validateRecoveryCode:recoveryCode];
}

+ (BOOL) validateRecoveryPuk:(NSString*)recoveryCode
{
    return [PowerAuthCoreOtpUtil validateRecoveryPuk:recoveryCode];
}

+ (PowerAuthActivationCode*) parseFromActivationCode:(NSString*)activationCode
{
    return [[PowerAuthCoreOtpUtil parseFromActivationCode:activationCode] toSdkActivationCode];
}

+ (PowerAuthActivationCode*) parseFromRecoveryCode:(NSString*)recoveryCode
{
    return [[PowerAuthCoreOtpUtil parseFromRecoveryCode:recoveryCode] toSdkActivationCode];
}

@end



@implementation PowerAuthCoreOtp (SDKExtension)

- (PowerAuthActivationCode*) toSdkActivationCode
{
    return [[PowerAuthActivationCode alloc] initWithCoreActivationCode:self];
}

@end
