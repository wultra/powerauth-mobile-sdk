/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PowerAuthSDK+Private.h"
#import "PA2PrivateEncryptorFactory.h"
#import "PA2RestApiEndpoint.h"
#import "PA2PrivateMacros.h"

@implementation PowerAuthSDK (CryptoHelper)

- (PA2ECIESEncryptor*) encryptorWithId:(PA2EncryptorId)encryptorId
{
	// The encryptors factory requires PA2Session & possesion unlock key for a proper operation.
	// After the enctyptor is created, we can destroy it.
	return [[[PA2PrivateEncryptorFactory alloc] initWithSession:self.session deviceRelatedKey:[self deviceRelatedKey]]
			encryptorWithId:encryptorId];
}

- (PA2AuthorizationHttpHeader*) authorizationHeaderForData:(NSData*)data
												  endpoint:(PA2RestApiEndpoint*)endpoint
											authentication:(PowerAuthAuthentication*)authentication
													 error:(NSError**)error
{
	if (self.hasPendingProtocolUpgrade) {
		if (!endpoint.isAvailableInProtocolUpgrade) {
			if (error) {
				*error = PA2MakeError(PA2ErrorCodePendingProtocolUpgrade, @"Request is temporarily unavailable, due to pending protocol upgrade.");
			}
			return nil;
		}
	}
	PA2HTTPRequestData * requestData = [[PA2HTTPRequestData alloc] init];
	requestData.body = data;
	requestData.method = endpoint.method;
	requestData.uri = endpoint.authUriId;
	PA2HTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
														 authentication:authentication
																  error:error];
	return [PA2AuthorizationHttpHeader authorizationHeaderWithValue:signature.authHeaderValue];
}

@end

@implementation PA2KeychainConfiguration (BiometricAccess)

- (PA2KeychainItemAccess) biometricItemAccess
{
	if (self.linkBiometricItemsToCurrentSet) {
		return PA2KeychainItemAccess_CurrentBiometricSet;
	} else {
		return PA2KeychainItemAccess_AnyBiometricSet;
	}
}

@end
