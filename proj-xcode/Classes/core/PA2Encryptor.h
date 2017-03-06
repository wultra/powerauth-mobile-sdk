/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2Types.h"

#pragma mark Encryptor -

/**
 The PA2EncryptorMode enum defines all encryption modes supported by
 the PA2Encryptor object.
 */
typedef NS_ENUM(int, PA2EncryptorMode) {
	/**
	 Encryptor works in nonpersonalized mode.
	 */
	PA2EncryptorMode_Nonpersonalized  = 0,
	/**
	 Encryptor works in personalized mode.
	 */
	PA2EncryptorMode_Personalized = 1,
};

/**
 The PA2Encryptor object provides an End-To-End Encryption between the client
 and the server. This class is used for both personalized and nonpersonalized
 E2EE modes of PA2 protocol.
 
 The direct instantiation of the object is not recommended but you can use the
 PA2Session class for this purpose. You can use PA2Session's 
 -nonpersonalizedEncryptorForSessionIndex or -personalizedEncryptorForSessionIndex:keys
 methods depending on what kind of encryptor you need.
 */
@interface PA2Encryptor : NSObject

/**
 Contains error code from last executed operation. You can use
 this value for debug purposes.
 */
@property (nonatomic, assign, readonly) PA2CoreErrorCode lastErrorCode;

/**
 Returns current encryption mode.
 */
@property (nonatomic, assign, readonly) PA2EncryptorMode encryptionMode;

/**
 Returns session index used during the encryptor object creation.
 */
@property (nonatomic, strong, readonly, nonnull) NSData * sessionIndex;

/**
 Encrypts a given bytes from |data| parameter and returns PA2EncryptedMessage object
 with the result. The method fills appropriate properties of the message depending on the mode
 of encryption. For more details, check the PA2EncryptedMessage documentation.
 
 Returns an PA2EncryptedMessage object if succeeded or nil in case of failure. 
 The lastErrorCode is updated to the following values:
	EC_Ok			if operation succeeded
	EC_Encryption	if internal encryption operation failed
 */
- (nullable PA2EncryptedMessage*) encrypt:(nonnull NSData*)data;

/**
 Decrypts data from |message| and returns NSData object with decrypted bytes.
 The PA2EncryptedMessage object must contain all mandatory properties for current
 encryption mode. For more details, check the PA2EncryptedMessage documentation.
 
 Returns a NSData object if succeeded or nil in case of failure.
 The lastErrorCode is updated to the following values:
	EC_Ok			if operation succeeded
	EC_WrongParam	if the provided message contains invalid data or
					if some required property is missing
	EC_Encryption	if the decryption operation failed

 */
- (nullable NSData*) decrypt:(nonnull PA2EncryptedMessage*)message;


@end
