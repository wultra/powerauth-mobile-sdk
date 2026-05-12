/*
 * Copyright 2025 Wultra s.r.o.
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

#import "PowerAuthClientConfiguration.h"
#import "PowerAuthRestApiErrorResponse.h"
#import "PowerAuthOperationTask.h"

#import "PA2TimeSynchronizationService.h"
#import "PA2KeystoreService.h"

@class PowerAuthCoreRequest;

/// Initializes client for given PowerAuthClientConfiguration configuration, completion queue,
/// base url and the session interface.
@interface PA2CoreHttpClient : NSObject<NSURLSessionDelegate>

- (nonnull instancetype) initWithConfiguration:(nonnull PowerAuthClientConfiguration*)configuration
                              sessionInterface:(nonnull id<PA2SessionInterface>)sessionInterface
                               completionQueue:(nonnull dispatch_queue_t)queue
                                       baseUrl:(nonnull NSString*)baseUrl;

/// Contains NSURLSession object created during the client initialization.
@property (nonatomic, strong, nonnull, readonly) NSURLSession * urlSession;

/// Contains serialization queue. The queue is unique per PA2HttpClient instance, so basically
/// each instance of PowerAuthSDK has its own queue.
///
/// Note that the queue may be blocked for an indefinite amount of time, when the biometry
/// authentication is requested. The reason for that is that the entry, protected by biometry,
/// needs to be acquired from the underlying keychain.
@property (nonatomic, strong, nonnull, readonly) NSOperationQueue * serialQueue;

/// Contains concurrent queue. Note that this queue is shared between multiple PA2HttpClient
/// instances.
@property (nonatomic, strong, nonnull, readonly) NSOperationQueue * concurrentQueue;

/// Contains session interface to get low level access to the session.
@property (nonatomic, strong, nonnull, readonly) id<PA2SessionInterface> sessionInterface;

/// Add core HTTP request for execution.
/// - Parameters:
///   - request: Request to execute.
///   - completion: Completion callback.
/// - Returns: Operation task representing asynchronous operation.
- (nonnull id<PowerAuthOperationTask>) postCoreRequest:(nonnull PowerAuthCoreRequest*)request
                                            completion:(void(^_Nonnull)(PowerAuthCoreRequest * _Nonnull request, id _Nullable response, NSError * _Nullable error))completion;

/// Add core task for execution.
/// - Parameters:
///   - task: Task to execute.
///   - completion: Completion callback.
/// - Returns: Operation task representing asynchronous operation.
- (nonnull id<PowerAuthOperationTask>) postCoreTask:(nonnull PowerAuthCoreTask*)task
                                         completion:(void(^_Nonnull)(PowerAuthCoreTask * _Nonnull task, id _Nullable response, NSError * _Nullable error))completion;

@end


#if defined(DEBUG)
/// The `FailureSimulator` category allows you to simulate HTTP request failure for any upcoming request.
/// Note that the feature is global, independent on actual PowerAuthSDK instance. The feature should be used only
/// for the testing purposes.
@interface PA2CoreHttpClient (FailureSimulator)

/// Set the next HTTP response with given relative path as failed with provided status code.
/// - Parameters:
///   - statusCode: Status code to report.
///   - relativePath: Relative path. If you use `nil` or `"*"`, then any request will fail.
+ (void) setNextResponseFailure:(nullable NSString*)relativePath
                     statusCode:(NSInteger)statusCode;

/// Set the next HTTP request with given relative path as failed on network error. The failure
/// happens while sending the request, so no data is received on the server.
/// - Parameters:
///   - relativePath: Relative path. If you use `nil` or `"*"`, then any request will fail.
+ (void) setNextRequestNetworkFailureOnSend:(nullable NSString*)relativePath
                                repeatCount:(NSInteger)count;

/// Set the next HTTP request with given relative path as failed on network error. The failure
/// happens while receiving the response, so server successfully received the request.
/// - Parameters:
///   - relativePath: Relative path. If you use `nil` or `"*"`, then any request will fail.
+ (void) setNextRequestNetworkFailureOnReceive:(nullable NSString*)relativePath;


/// Remove all failure hooks
+ (void) clearAllFailureHooks;
@end
#endif // DEBUG
