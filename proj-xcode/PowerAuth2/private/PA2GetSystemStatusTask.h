/*
 * Copyright 2023 Wultra s.r.o.
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
#import <PowerAuth2/PowerAuthServerStatus.h>
#import "PA2GroupedTask.h"
#import "PA2GetServerStatusResponse.h"

/// The `PA2SystemStatusProvider` protocol provide interface for getting system status from the server.
@protocol PA2SystemStatusProvider <NSObject>
@required
/// Get system status from the server.
/// - Parameters:
///   - callback: Callback to called with the system status.
///   - callbackQueue: Queue for the callback execution.
/// - Returns: Object representing an asynchronous cancelable operation.
- (id<PowerAuthOperationTask>) getSystemStatusWithCallback:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
                                             callbackQueue:(dispatch_queue_t)callbackQueue;
@end

@class PA2GetSystemStatusTask;

/// The `PA2GetSystemStatusTaskDelegate` protocol allows class that create `PA2GetSystemStatusTask` object
/// monitor the task completion.
@protocol PA2GetSystemStatusTaskDelegate <NSObject>
@required
/// Called when the get activation task complete its execution.
- (void) getSystemStatusTask:(PA2GetSystemStatusTask*)task didFinishedWithStatus:(PA2GetServerStatusResponse*)status error:(NSError*)error;
@end

@class PA2HttpClient;

/// The `PA2GetSystemStatusTask` implements grouped task that gets server status information from the server.
@interface PA2GetSystemStatusTask : PA2GroupedTask<PA2GetServerStatusResponse*>
/// Initialize object with shared lock and delegate.
/// - Parameters:
///   - httpClient: HTTP client implementation.
///   - sharedLock: Shared lock.
///   - delegate: Delegate.
- (instancetype) initWithHttpClient:(PA2HttpClient*)httpClient
                         sharedLock:(id<NSLocking>)sharedLock
                           delegate:(id<PA2GetSystemStatusTaskDelegate>)delegate;
@end

