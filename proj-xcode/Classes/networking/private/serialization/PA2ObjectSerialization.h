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

#import "PA2Response.h"
#import "PA2EncryptedRequest.h"
#import "PA2EncryptedResponse.h"
#import "PA2ECIESEncryptor.h"

/**
 The `PA2ObjectSerialization` class provides several static methods
 for network object to JSON serialization, and vice versa.
 */
@interface PA2ObjectSerialization : NSObject

/**
 Serializes PA2NetworkObject into JSON data. If the object is nil, then
 data with an empty brackets is returned (e.g. "{}")
 */
+ (NSData*) serializeObject:(id<PA2Encodable>)object;

/**
 Deserializes PA2NetworkObject from JSON Data. You must specify an object's class to
 proper deserialization.
 */
+ (id<PA2Decodable>) deserializeObject:(NSData*)data forClass:(Class)aClass error:(NSError**)error;

@end


@interface PA2ObjectSerialization (RequestResponse)

/**
 Serializes PA2NetworkObject into JSON data. The object is embedded into PA2Response
 before the serialization. If the object is nil, then data with an empty brackets
 is returned (e.g. "{}")
 */
+ (NSData*) serializeRequestObject:(id<PA2Encodable>)object;

/**
 Deserializes PA2Response from JSON data. You must specify an embedded object's class
 to proper deserialization.
 */
+ (PA2Response*) deserializeResponseObject:(NSData*)data forClass:(Class)aClass error:(NSError**)error;

@end


@interface PA2ObjectSerialization (E2EE)

/**
 Encrypts given object with provided encryptor and returns encrypted request object.
 */
+ (PA2EncryptedRequest*) encryptObject:(id<PA2Encodable>)object
							 encryptor:(PA2ECIESEncryptor*)encryptor
								 error:(NSError**)error;

/**
 
 */
+ (id<PA2Decodable>) decryptObject:(PA2EncryptedResponse*)response
						  forClass:(Class)aClass
						 decryptor:(PA2ECIESEncryptor*)decryptor
							 error:(NSError**)error;
/**
 */
+ (NSData*) decryptData:(NSData*)data
			  decryptor:(PA2ECIESEncryptor*)decryptor
				  error:(NSError**)error;

@end
