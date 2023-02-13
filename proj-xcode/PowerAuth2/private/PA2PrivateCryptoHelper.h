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

#import "PA2PrivateEncryptorFactory.h"

@class PA2RestApiEndpoint;
@class PowerAuthAuthorizationHttpHeader;
@class PowerAuthCoreEciesEncryptor;
@class PowerAuthAuthentication;

/**
 The `PA2PrivateCryptoHelper` protocol provides a minimal interface for
 a several cryptographic tasks required internally in the SDK, but provided
 by the PowerAuthSDK instance. The main purpose of this separation is to
 do not import public `"PowerAuthSDK.h"` header from SDK internals.
 */
@protocol PA2PrivateCryptoHelper

/**
 Returns ECIES encryptor for given identifier.
 */
- (PowerAuthCoreEciesEncryptor*) encryptorWithId:(PA2EncryptorId)encryptorId
                                           error:(NSError**)error;

/**
 Calculates PowerAuth signature for data & endpoint.
 */
- (PowerAuthAuthorizationHttpHeader*) authorizationHeaderForData:(NSData*)data
                                                  endpoint:(PA2RestApiEndpoint*)endpoint
                                            authentication:(PowerAuthAuthentication*)authentication
                                                     error:(NSError**)error;

@end
