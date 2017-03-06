/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
#import "PA2Networking.h"

@interface PA2Client : NSObject <NSURLSessionDelegate>

@property (nonatomic, assign) NSTimeInterval defaultRequestTimeout;
@property (nonatomic, strong, nonnull) NSString *baseEndpointUrl;
@property (nonatomic, strong, nullable) id<PA2ClientSslValidationStrategy> sslValidationStrategy;

- (nonnull NSURLSessionDataTask*) postToUrl:(nonnull NSURL*)url
									   data:(nonnull NSData*)data
									headers:(nullable NSDictionary*)headers
								 completion:(nonnull void(^)(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error))completion;

- (nonnull NSURLSessionDataTask*) postToUrl:(nonnull NSURL*)absoluteUrl
							  requestObject:(nullable id<PA2NetworkObject>)requestObject
									headers:(nullable NSDictionary*)headers
						responseObjectClass:(nullable Class)responseObjectClass
								   callback:(nonnull void(^)(PA2RestResponseStatus status, id<PA2NetworkObject> _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) createActivation:(nonnull PA2CreateActivationRequest*)request
										  callback:(nonnull void(^)(PA2RestResponseStatus status, PA2CreateActivationResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) getActivationStatus:(nonnull PA2ActivationStatusRequest*)request
											 callback:(nonnull void(^)(PA2RestResponseStatus status, PA2ActivationStatusResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) removeActivationSignatureHeader:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
														 callback:(nonnull void(^)(PA2RestResponseStatus status, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) vaultUnlockSignatureHeader:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
													callback:(nonnull void(^)(PA2RestResponseStatus status, PA2VaultUnlockResponse * _Nullable response, NSError * _Nullable error))callback;

@end
