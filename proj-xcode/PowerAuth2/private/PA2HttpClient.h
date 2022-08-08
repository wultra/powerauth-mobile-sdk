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

#import <PowerAuth2/PowerAuthClientConfiguration.h>
#import <PowerAuth2/PowerAuthRestApiErrorResponse.h>

#import "PA2HttpRequest.h"
#import "PA2RestApiEndpoint.h"
#import "PA2PrivateCryptoHelper.h"
#import "PA2SessionInterface.h"

/**
 The `PA2HttpClient` class provides a high level networking functionality,
 including encryption & data signing for the mobile SDK. The class is internal
 and cannot be used by the application.
 
 Note that there's always only one instance of this client, per PowerAuthSDK
 object instance.
 */
@interface PA2HttpClient : NSObject<NSURLSessionDelegate>

/**
 Initializes client for given PowerAuthClientConfiguration configuration, completion queue,
 base url, crypto helper and session interface.
 */
- (nonnull instancetype) initWithConfiguration:(nonnull PowerAuthClientConfiguration*)configuration
                               completionQueue:(nonnull dispatch_queue_t)queue
                                       baseUrl:(nonnull NSString*)baseUrl
                          coreSessionInterface:(nonnull id<PA2SessionInterface>)sessionInterface
                                        helper:(nonnull id<PA2PrivateCryptoHelper>)helper;

@property (nonatomic, weak, nullable, readonly) id<PA2PrivateCryptoHelper> cryptoHelper;
@property (nonatomic, strong, nonnull, readonly) id<PA2SessionInterface> sessionInterface;
@property (nonatomic, strong, nonnull, readonly) PowerAuthClientConfiguration * configuration;
@property (nonatomic, strong, nonnull, readonly) NSString * baseUrl;

/**
 Contains NSURLSession object created during the client initialization.
 */
@property (nonatomic, strong, nonnull, readonly) NSURLSession * session;
/**
 Contains serialization queue. The queue is unique per PA2HttpClient instance, so basically
 each instnace of PowerAuthSDK has its own queue.
 
 Note that the queue may be blocked for an indefinite amount of time, when the biometry
 signature is requested. The reson for that is that the entry, protected by biometry,
 needs to be acquired from the underlying keychain.
 */
@property (nonatomic, strong, nonnull, readonly) NSOperationQueue * serialQueue;
/**
 Contains concurrent queue. Note that this queue is shared between multiple PA2HttpClient
 instances.
 */
@property (nonatomic, strong, nonnull, readonly) NSOperationQueue * concurrentQueue;

/**
 Post a HTTP request to the the given endpoint. The object and authentication parameters are optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 */
- (nonnull NSOperation*) postObject:(nullable id<PA2Encodable>)object
                                 to:(nonnull PA2RestApiEndpoint*)endpoint
                               auth:(nullable PowerAuthAuthentication*)authentication
                         completion:(void(^ _Nonnull)(PowerAuthRestApiResponseStatus status, id<PA2Decodable> _Nullable response, NSError * _Nullable error))completion;

/**
 Post a HTTP request to the the given endpoint. The object parameter is optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 */
- (nonnull NSOperation*) postObject:(nullable id<PA2Encodable>)object
                                 to:(nonnull PA2RestApiEndpoint*)endpoint
                         completion:(void(^ _Nonnull)(PowerAuthRestApiResponseStatus status, id<PA2Decodable> _Nullable response, NSError * _Nullable error))completion;

/**
 Post a HTTP request to the the given endpoint. The object and authentication parameters are optional.
 The completion block is always issued to the "completionQueue", provided in the object's initialization.
 
 The cancel block is called if application calls "cancel" on returned operation. This allows SDK to handle
 special cases, where the consistency needs to be guaranteed.
 */
- (nonnull NSOperation*) postObject:(nullable id<PA2Encodable>)object
                                 to:(nonnull PA2RestApiEndpoint*)endpoint
                               auth:(nullable PowerAuthAuthentication*)authentication
                         completion:(void(^ _Nonnull)(PowerAuthRestApiResponseStatus status, id<PA2Decodable> _Nullable response, NSError * _Nullable error))completion
                             cancel:(void(^ _Nullable)(void))cancel;

@end
