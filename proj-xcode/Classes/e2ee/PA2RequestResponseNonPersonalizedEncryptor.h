/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2Encryptor.h"
#import "PA2NonPersonalizedEncryptedObject.h"
#import "PA2Request.h"
#import "PA2Response.h"
#import "PA2EncryptorProtocol.h"

@interface PA2RequestResponseNonPersonalizedEncryptor : NSObject <PA2EncryptorProtocol>

/** Initialize a new high-level encryptor with a low-level encryptor instance generated with provided session instance.
 
 @param encryptor Low-level encryptor used for data encryption / decryption.
 @return New instance of high-level encryptor.
 */
- (instancetype)initWithEncryptor:(PA2Encryptor*)encryptor;

@end
