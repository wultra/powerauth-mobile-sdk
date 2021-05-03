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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

@class PowerAuthCoreEciesCryptogram;
@class PowerAuthCoreEciesMetaData;

#pragma mark - ECIES Encryptor -

/**
 The `PowerAuthCoreEciesEncryptor` class implements a request encryption and response decryption for our custom ECIES scheme.
 For more details about our ECIES implementation, please check documentation available at the beginning of
 <PowerAuth/ECIES.h> C++ header.
 */
@interface PowerAuthCoreEciesEncryptor : NSObject

#pragma mark Initialization

/**
 Initializes an ecnryptor with server's |publicKey| and optional |sharedInfo1| and |sharedInfo2|.
 The initialized instance can be used for both encryption and decryption tasks.
 */
- (nullable instancetype) initWithPublicKey:(nonnull NSData*)publicKey
								sharedInfo1:(nullable NSData*)sharedInfo1
								sharedInfo2:(nullable NSData*)sharedInfo2;

/**
 Returns a new instance of PowerAuthCoreEciesEncryptor, suitable only for data decryption or nil if current encryptor is not
 able to decrypt response (this happens typically if you did not call `encryptRequest` or instnace contains invalid keys).
 
 Discussion
 
 The returned copy will not be able to encrypt a new requests, but will be able to decrypt a received response.
 This behavior is helpful when processing of simultaneous encrypted requests and resonses is required.
 Due to fact, that our ECIES scheme is generating an unique key for each request-response roundtrip, you need to
 capture that key for later safe decryption. As you can see, that might be problematic, because you don't know when
 exactly the response will be received. To help with this, you can make a copy of the object and use that copy
 only for response decryption.
 
 The `-encryptRequest:completion:` method is an one example of safe approach, but you can implement your own
 processing, if the thread safety is not a problem.
 */
- (nullable PowerAuthCoreEciesEncryptor*) copyForDecryption;

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
 The property typically contains NO only when the instance is not properly initialized, or
 you did not call `encryptRequest` at least once.
 */
@property (nonatomic, readonly) BOOL canDecryptResponse;

#pragma mark Encrypt & Decrypt

/**
 Encrypts an input |data| into PowerAuthCoreEciesCryptogram object or nil in case of failure.
 Note that each call for this method will regenerate an internal envelope key, so you should use
 the method only in pair with subsequent call to `decryptResponse:`. If you plan to reuse one
 encryptor for multiple simultaneous requests, then you should make a copy of the object after
 every successful encryption. Check `-copyForDecryption` or  `-encryptRequest:completion:` methods
 for details.
 
 The DEBUG version of the SDK prints detailed error about the failure reason into the log.
 */
- (nullable PowerAuthCoreEciesCryptogram *) encryptRequest:(nullable NSData *)data;

/**
 Decrypts a |cryptogram| received from the server and returns decrypted data or nil in case of failure.
 
 The DEBUG version of the SDK prints detailed error about the failure reason into the log.
 */
- (nullable NSData *) decryptResponse:(nonnull PowerAuthCoreEciesCryptogram *)cryptogram;

/**
 This is a special, thread-safe version of request encryption. The method encrypts provided data
 and makes a copy of itself in thread synchronized block. Then the completion block is called with
 generated cryptogram and copied instance, which is suitable only for response decryption.
 The completion is called from outside of the synchronization block.
 
 Note that the rest of the encryptor's interface is not thread safe. So, once the shared instance
 for encryption is created, then you should not change its parameters or call other methods.
 
 Returns YES if encryption succeeded or NO in case of error.
 */
- (BOOL) encryptRequest:(nullable NSData *)data
			 completion:(void (NS_NOESCAPE ^_Nonnull)(PowerAuthCoreEciesCryptogram * _Nullable cryptogram, PowerAuthCoreEciesEncryptor * _Nullable decryptor))completion;


#pragma mark Associated metadata

/**
 Contains metadata associated to this encryptor. The assigned object is not required for an actual
 request encryption, but it's useful for correct HTTP request & response processing.
 */
@property (nonatomic, strong, nullable) PowerAuthCoreEciesMetaData * associatedMetaData;

@end


#pragma mark - ECIES cryptogram -

/**
 The `PowerAuthCoreEciesCryptogram` object represents cryptogram transmitted
 over the network.
 */
@interface PowerAuthCoreEciesCryptogram : NSObject

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
 Nonce for IV derivation. The value is optional for response data.
 */
@property (nonatomic, strong, nullable) NSData * nonce;

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
/**
 Nonce for IV derivation in Base64 format. The value is mapped
 to the `nonce` property.
 */
@property (nonatomic, strong, nullable) NSString * nonceBase64;
@end


#pragma mark - ECIES metadata -

/**
 The `PowerAuthCoreEciesMetaData` object represents an additional data associated
 to the ECIES encryptor. The content stored in this object is typically
 required for the correct HTTP request & response processing, but is not
 involved in the actual data encryption.
 */
@interface PowerAuthCoreEciesMetaData : NSObject

/**
 Initializes object with required `applicationKey` and with optional `activationIdentifier`
 */
- (nonnull instancetype) initWithApplicationKey:(nonnull NSString*)applicationKey
						   activationIdentifier:(nullable NSString*)activationIdentifier;

/**
 Contains required application key required for the HTTP header construction.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * applicationKey;

/**
 Contains optional activation identifier.
 */
@property (nonatomic, strong, readonly, nullable) NSString * activationIdentifier;


#pragma mark - HTTP

/**
 Returns key for HTTP header.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * httpHeaderKey;

/**
 Returns value for HTTP header.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * httpHeaderValue;

@end
