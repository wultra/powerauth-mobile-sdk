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

#import "PA2PublicNetworking.h"

@interface PA2Client : NSObject <NSURLSessionDelegate>

@property (nonatomic, assign) NSTimeInterval defaultRequestTimeout;
@property (nonatomic, strong, nonnull) NSString *baseEndpointUrl;
@property (nonatomic, strong, nullable) id<PA2ClientSslValidationStrategy> sslValidationStrategy;

/** Build absolute URL for given resource using given base URL.
 
 @param urlPath Path to the resource, relative to given base URL.
 @return Absolute URL for given resource.
 */
- (nonnull NSURL*) urlForRelativePath:(nonnull NSString*)urlPath;

/**
 Embeds PA2NetworkObject into PA2Request object and returns serialized NSData object with
 serialized JSON.
 */
- (nonnull NSData*) embedNetworkObjectIntoRequest:(nullable id<PA2NetworkObject>)object;

- (nonnull NSURLSessionDataTask*) postToUrl:(nonnull NSURL*)url
									   data:(nonnull NSData*)data
									headers:(nullable NSDictionary*)headers
								 completion:(nonnull void(^)(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error))completion;

- (nonnull NSURLSessionDataTask*) postToUrl:(nonnull NSURL*)absoluteUrl
							  requestObject:(nullable id<PA2NetworkObject>)requestObject
									headers:(nullable NSDictionary*)headers
						responseObjectClass:(nullable Class)responseObjectClass
								   callback:(nonnull void(^)(PA2RestResponseStatus status, id<PA2NetworkObject> _Nullable response, NSError * _Nullable error))callback;

@end
