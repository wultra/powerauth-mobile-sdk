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

#import "PowerAuthSDK+Private.h"
#import "PA2PrivateEncryptorFactory.h"
#import "PA2RestApiEndpoint.h"
#import "PA2PrivateMacros.h"

@implementation PowerAuthSDK (CryptoHelper)

- (PowerAuthCoreEciesEncryptor*) encryptorWithId:(PA2EncryptorId)encryptorId
{
	// The encryptors factory requires PowerAuthCoreSession & possesion unlock key for a proper operation.
	// After the enctyptor is created, we can destroy it.
	return [[[PA2PrivateEncryptorFactory alloc] initWithSession:self.session deviceRelatedKey:[self deviceRelatedKey]]
			encryptorWithId:encryptorId];
}

- (PowerAuthAuthorizationHttpHeader*) authorizationHeaderForData:(NSData*)data
												  endpoint:(PA2RestApiEndpoint*)endpoint
											authentication:(PowerAuthAuthentication*)authentication
													 error:(NSError**)error
{
	if (self.hasPendingProtocolUpgrade || self.hasProtocolUpgradeAvailable) {
		if (!endpoint.isAvailableInProtocolUpgrade) {
			if (error) {
				*error = PA2MakeError(PowerAuthErrorCode_PendingProtocolUpgrade, @"Request is temporarily unavailable, due to required or pending protocol upgrade.");
			}
			return nil;
		}
	}
	PowerAuthCoreHTTPRequestData * requestData = [[PowerAuthCoreHTTPRequestData alloc] init];
	requestData.body = data;
	requestData.method = endpoint.method;
	requestData.uri = endpoint.authUriId;
	PowerAuthCoreHTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
																   authentication:authentication
																			error:error];
	return [PowerAuthAuthorizationHttpHeader authorizationHeaderWithValue:signature.authHeaderValue];
}

@end

@implementation PowerAuthKeychainConfiguration (BiometricAccess)

- (PowerAuthKeychainItemAccess) biometricItemAccess
{
	if (self.allowBiometricAuthenticationFallbackToDevicePasscode) {
		return PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode;
	} else if (self.linkBiometricItemsToCurrentSet) {
		return PowerAuthKeychainItemAccess_CurrentBiometricSet;
	} else {
		return PowerAuthKeychainItemAccess_AnyBiometricSet;
	}
}

@end
