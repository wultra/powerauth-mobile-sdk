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

#import "PA2OtpUtil.h"

@implementation PA2Otp
@end

@implementation PA2OtpUtil

+ (PA2Otp*) parseFromActivationCode:(NSString*)activationCode {
	
	// Prepare the regex
	NSRange searchedRange = NSMakeRange(0, [activationCode length]);
	NSString *pattern = @"^([A-Z2-7]{5,5}-[A-Z2-7]{5,5})-([A-Z2-7]{5,5}-[A-Z2-7]{5,5})(#([A-Za-z0-9/+=]*))?$";
	NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
	
	// Find first matching result
	NSTextCheckingResult *match = [regex firstMatchInString:activationCode options:0 range:searchedRange];
	if ([match numberOfRanges] < 4) {
		return nil;
	}
	
	// Get values from the activation code, check for the ranges
	NSRange activationIdShortRange = [match rangeAtIndex:1];
	if (activationIdShortRange.location == NSNotFound) {
		return nil;
	}
	NSString *activationIdShort = [activationCode substringWithRange:activationIdShortRange];
	
	NSRange activationOtpRange = [match rangeAtIndex:2];
	if (activationOtpRange.location == NSNotFound) {
		return nil;
	}
	NSString *activationOtp = [activationCode substringWithRange:activationOtpRange];
	
	// Activation signature is optional...
	NSRange activationSignatureRange = [match rangeAtIndex:4];
	NSString *activationSignature = nil;
	if (activationSignatureRange.location != NSNotFound) {
		activationSignature = [activationCode substringWithRange:activationSignatureRange];
	}
	
	// Prepare result and return
	PA2Otp *result = [[PA2Otp alloc] init];
	result.activationIdShort = activationIdShort;
	result.activationOtp = activationOtp;
	result.activationSignature = activationSignature;
	
	return result;
}

@end
