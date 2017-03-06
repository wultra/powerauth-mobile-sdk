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

#import <Foundation/Foundation.h>

@interface PA2Otp : NSObject
@property (nonatomic, strong) NSString* activationIdShort;
@property (nonatomic, strong) NSString* activationOtp;
@property (nonatomic, strong) NSString* activationSignature;
@end

/** Class used for validating OTP activation code.
 */
@interface PA2OtpUtil : NSObject

/** Parse activation code to the structured OTP information.
 
 @param activationCode Activation code, 4x5 Base32 characters ("XXXXX-XXXXX-XXXXX-XXXXX").
 @return Structured OTP information.
 */
+ (PA2Otp*) parseFromActivationCode:(NSString*)activationCode;

@end
