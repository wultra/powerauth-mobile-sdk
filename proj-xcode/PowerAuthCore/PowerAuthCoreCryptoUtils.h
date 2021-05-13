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

#import <Foundation/Foundation.h>

@class PowerAuthCoreECPublicKey;

/**
 The `PowerAuthCoreCryptoUtils` class provides a several general cryptographic primitives
 required in our other open source libraries.
 */
@interface PowerAuthCoreCryptoUtils : NSObject

/**
 Validates ECDSA signature for given data and EC public key.
 */
+ (BOOL) ecdsaValidateSignature:(nonnull NSData*)signature
						forData:(nonnull NSData*)data
				   forPublicKey:(nonnull PowerAuthCoreECPublicKey*)publicKey;

/**
 Computes SHA-256 from given data.
 */
+ (nonnull NSData*) hashSha256:(nonnull NSData*)data;

/**
 Computes HMAC-SHA-256 for given data and key. Returns nil in case that underlying
 implementation fail.
 */
+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data 
						   key:(nonnull NSData*)key;

/**
 Computes HMAC-SHA-256 with requested length for given data and key. Returns nil in
 case that underlying implementation fail.
 */
+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data
						   key:(nonnull NSData*)key
						length:(NSUInteger)length;

/**
 Generates a required amount of random bytes. Returns nil in case that 
 underlying random generator is broken.
 */
+ (nullable NSData*) randomBytes:(NSUInteger)count;

@end


/**
 The `PowerAuthCoreECPublicKey` is an object representing public key in cryptography
 based on elliptic curves.
 */
@interface PowerAuthCoreECPublicKey: NSObject

/**
 Initializes object with EC public key data.
 Returns nil if invalid data is provided.
 */
- (nullable id) initWithData:(nonnull NSData*)publicKeyData;

@end
