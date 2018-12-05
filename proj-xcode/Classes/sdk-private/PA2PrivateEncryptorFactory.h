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

#import "PA2PrivateTypes.h"

@class PA2Session;
@class PA2ECIESEncryptor;

@interface PA2PrivateEncryptorFactory : NSObject

/**
 Initializes object with required session & optional device related key.
 The device related key is required only for activation scoped encryptors.
 */
- (instancetype) initWithSession:(PA2Session*)session
				deviceRelatedKey:(NSData*)deviceRelatedKey;

/**
 Constructs a new encryptor depending on encryptor identifier.
 The returned encryptor must not be reused, so the encryptor object has to be
 newly constructed.
 */
- (PA2ECIESEncryptor*) encryptorWithId:(PA2EncryptorId)encryptorId;

@end
