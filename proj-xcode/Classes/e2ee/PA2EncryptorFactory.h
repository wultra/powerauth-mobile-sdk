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

#import "PA2RequestResponseNonPersonalizedEncryptor.h"
#import "PA2Session.h"

@interface PA2EncryptorFactory : NSObject

/** Initialize the new instance of the encryptor factory with a weak reference to related PA2Session instance.
 
 @param session Instance of PA2Session, used for low-level encryptor generation.
 @return New instance of encryptor factory.
 */
- (instancetype)initWithSession:(PA2Session*)session;

/** Build a new encryptor used for the non-personalized encryption of request-response data cycle.
 
 This encryptor uses a single instance of PA2Encryptor for both request and response. It uses the same session index for
 both encrypting request and decrypting response using a non-personalized (application specific) encryption.
 
 @return New instance of encryptor used for request-response cycle.
 */
- (PA2RequestResponseNonPersonalizedEncryptor*) buildRequestResponseNonPersonalizedEncryptor;

@end
