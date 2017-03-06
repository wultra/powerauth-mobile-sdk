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

/** Protocol responsible for declaring methods related to encryption process.
 */
@protocol PA2EncryptorProtocol <NSObject>

/** Encrypt data using non-personalized (application key specific) or personalized (activation specific) encryption and return ready to use request object.
 
 @param requestData NSData with request body payload.
 @param error Error object, in case that an error occurs.
 @return New instance of a ready to use encrypted request, or nil if error occurs.
 */
- (nullable PA2Request<PA2EncryptedObject*>*) encryptRequestData:(nonnull NSData*)requestData
														   error:(NSError* _Nullable * _Nullable)error;

/** Decrypt encrypted response and return plain decrypted response data.
 
 @param response Instance of encrypted response.
 @param error Error object, in case that an error occurs.
 @return Decrypted response data, or nil if error occurs.
 */
- (nullable NSData*) decryptResponse:(nullable PA2Response<PA2EncryptedObject*>*)response
							   error:(NSError* _Nullable * _Nullable)error;

@end
