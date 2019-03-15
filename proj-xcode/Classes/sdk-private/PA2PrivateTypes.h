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

#import <Foundation/Foundation.h>

/**
 The `PA2EncryptorId` enumeration defines various types of
 ECIES encryptor configurations.
 */
typedef NS_ENUM(int, PA2EncryptorId) {
	/**
	 Constant for "no-encryptor"
	 */
	PA2EncryptorId_None,
	
	// Encryptors available for the application
	
	/**
	 Constructs a new encryptor for an application scope, which can be used for an
	 application's custom purposes. The application server can typically decrypt data,
	 encrypted with this configuration.
	 */
	PA2EncryptorId_GenericApplicationScope,
	/**
	 Constructs a new encryptor for an activation scope, which can be used for an
	 application's custom purposes. The application server can typically decrypt data,
	 encrypted with this configuration.
	 */
	PA2EncryptorId_GenericActivationScope,
	
	// Encryptors available only for SDK
	
	/**
	 Constructs a new encryptor for activation purposes.
	 In current SDK implementation, the method uses `PA2EncryptorId_GenericApplicationScope`
	 internally, so the payload encrypted with the returned object can be decrypted by
	 the application server.
	 */
	PA2EncryptorId_ActivationRequest,
	/**
	 Constructs a new encryptor for activation private purposes. The content encrypted
	 with this object can be decrypted only by the PowerAuth server.
	 
	 Note that the returned encryptor has no associated metadata.
	 */
	PA2EncryptorId_ActivationPayload,
	/**
	 Constructs a new encryptor for the protocol upgrade purposes. The content encrypted
	 with this object can be decrypted only by the PowerAuth server.
	 */
	PA2EncryptorId_UpgradeStart,
	/**
	 Constructs a new encryptor for the vault unlock request purposes. The content encrypted
	 with this object can be decrypted only by the PowerAuth server.
	 */
	PA2EncryptorId_VaultUnlock,
	/**
	 Constructs a new encryptor for the create token request purposes. The content encrypted
	 with this object can be decrypted only by the PowerAuth server.
	 */
	PA2EncryptorId_TokenCreate,
	/**
	 Constructs a new encryptor for the recovery code confirmation request. The content encrypted
	 with this object can be decrypted only by the PowerAuth server.
	 */
	PA2EncryptorId_ConfirmRecoveryCode
};
