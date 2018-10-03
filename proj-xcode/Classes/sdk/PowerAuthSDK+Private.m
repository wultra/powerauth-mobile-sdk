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
	return [self requestSignatureWithAuthentication:authentication
											 method:endpoint.method
											  uriId:endpoint.authUriId
											   body:data
											  error:error];
}

@end
