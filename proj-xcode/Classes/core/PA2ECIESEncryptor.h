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

#import <Foundation/Foundation.h>

@class PA2ECIESCryptogram;

#pragma mark - ECIES Encryptor -

/**
 The PA2ECIESEncryptor class implements a request encryption and response decryption for our custom ECIES scheme.
 For more details about our ECIES implementation, please check documentation available at the beginning of
 <PowerAuth/ECIES.h> C++ header.
 */
@interface PA2ECIESEncryptor : NSObject

#pragma mark Initialization

/**
 Initializes an ecnryptor with server's |publicKey| and optional |sharedInfo2|.
 The initialized instance can be used for both encryption and decryption tasks.
 */
- (nullable id) initWithPublicKey:(nonnull NSData*)publicKey sharedInfo2:(nullable NSData*)sharedInfo;

/**
 Initializes an encryptor with previously calculated |envelopeKey| and optional |sharedInfo|.
 The initialized instance can be used only for decryption task.
 */
- (nullable id) initWithEnvelopeKey:(nonnull NSData*)envelopeKey sharedInfo2:(nullable NSData*)sharedInfo;

#pragma mark Properties

/**
 Contains server's public key, provided during the object initialization. The value is optional, because
 you can create an encryptor object without the public key.
 */
@property (nonatomic, strong, readonly, nullable) NSData * publicKey;
/**
 Contains a value for optional shared info.
 */
@property (nonatomic, strong, nullable) NSData * sharedInfo2;
/**
 Contains YES if this instnace of encryptor can encrypt request data.
 */
@property (nonatomic, readonly) BOOL canEncryptRequest;
/**
 Contains YES if this instnace of encryptor can decrypt a cryptogram with response data.
 */
@property (nonatomic, readonly) BOOL canDecryptResponse;

#pragma mark Encrypt & Decrypt

/**
 Encrypts an input |data| into PA2ECIESCryptogram object or nil in case of failure.
 Note that each call for this method will regenerate an internal envelope key, so you should use
 the method only in pair with subsequent call to `decryptResponse:`.
 
 The DEBUG version of the SDK prints detailed error about the failure reason into the log.
 */
- (nullable PA2ECIESCryptogram *) encryptRequest:(nullable NSData *)data;

/**
 Decrypts a |cryptogram| received from the server and returns decrypted data or nil in case of failure.
 
 The DEBUG version of the SDK prints detailed error about the failure reason into the log.
 */
- (nullable NSData *) decryptResponse:(nonnull PA2ECIESCryptogram *)cryptogram;

@end


#pragma mark - ECIES cryptogram -

/**
 The PA2ECIESCryptogram object represents cryptogram transmitted
 over the network.
 */
@interface PA2ECIESCryptogram : NSObject

/**
 Encrypted data
 */
@property (nonatomic, strong, nullable) NSData * body;
/**
 A MAC computed for key & data
 */
@property (nonatomic, strong, nullable) NSData * mac;
/**
 An ephemeral EC public key. The value is optional for response data.
 */
@property (nonatomic, strong, nullable) NSData * key;

/**
 Encrypted data in Base64 format. The value is mapped
 to the `base` property.
 */
@property (nonatomic, strong, nullable) NSString * bodyBase64;
/**
 A MAC computed for key & data in Base64 format. The value is mapped
 to the `mac` property.
 */
@property (nonatomic, strong, nullable) NSString * macBase64;
/**
 An ephemeral EC public key in Base64 format. The value is mapped
 to the `mac` property.
 */
@property (nonatomic, strong, nullable) NSString * keyBase64;

@end
