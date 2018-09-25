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

#import "PA2Session.h"
#import "PA2ECIESEncryptor.h"

@interface PA2PrivateEncryptorFactory : NSObject

/**
 Initializes object with required session & optional device related key.
 The device related key is required only for activation scoped encryptors.
 */
- (instancetype) initWithSession:(PA2Session*)session
				deviceRelatedKey:(NSData*)deviceRelatedKey;

#pragma mark - Public encryptors

/**
 Constructs a new encryptor for an application scope, which can be used for an
 application's custom purposes. The application server can typically decrypt data,
 encrypted with this configuration.
 */
- (PA2ECIESEncryptor*) genericEncryptorForApplicationScope;

/**
 Constructs a new encryptor for an activation scope, which can be used for an
 application's custom purposes. The application server can typically decrypt data,
 encrypted with this configuration.
 */
- (PA2ECIESEncryptor*) genericEncryptorForActivationScope;


#pragma mark - SDK private purposes

/**
 Constructs a new encryptor for activation purposes.
 In current SDK implementation, the method uses `publicEncryptorForApplicationScope`
 internally, so the payload encrypted with the returned object can be decrypted by
 the application server.
 */
- (PA2ECIESEncryptor*) encryptorForActivationRequest;

/**
 Constructs a new encryptor for activation private purposes. The content encrypted
 with this object can be decrypted only by the PowerAuth server.
 
 Note that the returned encryptor has no associated metadata.
 */
- (PA2ECIESEncryptor*) encryptorForActivationPayload;

/**
 Constructs a new encryptor for the activation migration purposes. The content encrypted
 with this object can be decrypted only by the PowerAuth server.
 */
- (PA2ECIESEncryptor*) encryptorForMigrationStartRequest;

/**
 Constructs a new encryptor for the vault unlock request purposes. The content encrypted
 with this object can be decrypted only by the PowerAuth server.
 */
- (PA2ECIESEncryptor*) encryptorForVaultUnlockRequest;

/**
 Constructs a new encryptor for the create token request purposes. The content encrypted
 with this object can be decrypted only by the PowerAuth server.
 */
- (PA2ECIESEncryptor*) encryptorForCreateTokenRequest;

@end
