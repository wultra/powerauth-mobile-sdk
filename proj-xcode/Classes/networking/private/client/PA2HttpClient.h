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

#import "PA2HttpRequest.h"
#import "PA2RestApiEndpoint.h"
#import "PA2PrivateCryptoHelper.h"
#import "PA2ClientConfiguration.h"
#import "PA2RestResponseStatus.h"

/**
 The `PA2HttpClient` class provides a high level networking functionality,
 including encryption & data signing for the mobile SDK. The class is internal
 and cannot be used by the application.
 
 Note that there's always only one instance of this client, per PowerAuthSDK
 object instance.
 */
@interface PA2HttpClient : NSObject<NSURLSessionDelegate>

/**
 Initializes client for given PA2ClientConfiguration configuration, completion queue,
 base url and crypto helper.
 */
- (instancetype) initWithConfiguration:(PA2ClientConfiguration*)configuration
					   completionQueue:(dispatch_queue_t)queue
							   baseUrl:(NSString*)baseUrl
								helper:(id<PA2PrivateCryptoHelper>)helper;

@property (nonatomic, weak, readonly) id<PA2PrivateCryptoHelper> cryptoHelper;
@property (nonatomic, strong, readonly) PA2ClientConfiguration * configuration;
@property (nonatomic, strong, readonly) NSString * baseUrl;

/**
 Contains NSURLSession object created during the client initialization.
 */
@property (nonatomic, strong, readonly) NSURLSession * session;
/**
 Contains serialization queue. The queue is unique per PA2HttpClient instance, so basically
 each instnace of PowerAuthSDK has its own queue.
 
 Note that the queue may be blocked for an indefinite amount of time, when the biometry
 signature is requested. The reson for that is that the entry, protected by biometry,
 needs to be acquired from the underlying keychain.
 */
@property (nonatomic, strong, readonly) NSOperationQueue * serialQueue;
/**
 Contains concurrent queue. Note that this queue is shared between multiple PA2HttpClient
 instances.
 */
@property (nonatomic, strong, readonly) NSOperationQueue * concurrentQueue;

/**
 Post a HTTP request to the the given endpoint. The object and authentication parameters are optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 */
- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
					   auth:(PowerAuthAuthentication*)authentication
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion;

/**
 Post a HTTP request to the the given endpoint. The object parameter is optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 */
- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion;

/**
 Post a HTTP request to the the given endpoint. The object and authentication parameters are optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 
 The cancel block is called if application calls "cancel" on returned operation. This allows SDK to handle
 special cases, where the consistency needs to be guaranteed.
 */
- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
					   auth:(PowerAuthAuthentication*)authentication
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
					 cancel:(void(^)(void))cancel;

@end
