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

#import "PowerAuthTestServerModel.h"

@implementation PATSSystemStatus
@end

@implementation PATSApplication
@end

@implementation PATSApplicationVersion
@end

@implementation PATSApplicationVersionSupport
@end

@implementation PATSApplicationDetail
@end

@implementation PATSInitActivationResponse

- (NSString*) activationCodeWithSignature
{
	return [[[self activationCodeWithoutSignature] stringByAppendingString:@"#"] stringByAppendingString:_activationSignature];
}

- (NSString*) activationCodeWithoutSignature
{
	return [[_activationIdShort stringByAppendingString:@"-"] stringByAppendingString:_activationOTP];
}

@end

@implementation PATSCommitActivationResponse
@end

@implementation PATSSimpleActivationStatus
@end

@implementation PATSActivationStatus
@end

@implementation PATSEncryptionKey
@end

@implementation PATSVerifySignatureResponse
@end

@implementation PATSOfflineSignaturePayload
- (NSArray<NSString*>*) parsedComponents
{
	NSArray<NSString*>* components = [self.offlineData componentsSeparatedByString:@"\n"];
	if (components.count > 2) {
		NSString * nonce = [components objectAtIndex:components.count - 2];
		NSString * signS = [components objectAtIndex:components.count - 1];
		NSString * key   = [signS substringToIndex:1];
		NSString * sign  = [signS substringFromIndex:1];
		NSString * data  = [[components subarrayWithRange:NSMakeRange(0, components.count - 2)] componentsJoinedByString:@"\n"];
		return @[ data, nonce, key, sign ];
	}
	return nil;
}
- (NSString*) parsedData
{
	return [[self parsedComponents] objectAtIndex:0];
}
- (NSString*) parsedNonce
{
	return [[self parsedComponents] objectAtIndex:1];
}
- (NSString*) parsedSigningKey
{
	return [[self parsedComponents] objectAtIndex:2];
}
- (NSString*) parsedSignature
{
	return [[self parsedComponents] objectAtIndex:3];
}
- (NSString*) parsedSignedData
{
	NSArray<NSString*>* components = [self parsedComponents];
	if (components) {
		return [[components subarrayWithRange:NSMakeRange(0, components.count - 1)] componentsJoinedByString:@"\n"];
	}
	return nil;
}
@end

@implementation PATSToken
@end

@implementation PATSTokenValidationRequest
@end

@implementation PATSTokenValidationResponse
@end

@implementation PATSECIESCryptogram
@end

NSString * PATSActivationOtpValidationEnumToString(PATSActivationOtpValidationEnum val)
{
	switch (val) {
		case PATSActivationOtpValidation_NONE:
			return nil;
		case PATSActivationOtpValidation_ON_COMMIT:
			return @"ON_COMMIT";
		case PATSActivationOtpValidation_ON_KEY_EXCHANGE:
			return @"ON_KEY_EXCHANGE";
		default:
			return nil;
	}
}
