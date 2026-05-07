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

#import <PowerAuth2/PowerAuthTimeSynchronizationService.h>
#import <PowerAuth2/PowerAuthServerStatus.h>

#import <PowerAuthCore/PowerAuthCore.h>

@class PA2GetSystemStatusTask, PA2CoreHttpClient;

/// The `PA2GetSystemStatusTaskDelegate` protocol allows class that create `PA2GetSystemStatusTask` object
/// monitor the task completion.
@protocol PA2GetSystemStatusTaskDelegate <NSObject>
@required
/// Called when the get activation task complete its execution.
- (void) getSystemStatusTask:(PA2GetSystemStatusTask*)task didFinishedWithStatus:(PowerAuthServerStatus*)status error:(NSError*)error;
@end


/// The `PA2TimeSynchronizationService` class provides functionality to synchronize time with the server.
/// The class implements `PowerAuthTimeSynchronizationService` public protocol.
@interface PA2TimeSynchronizationService : NSObject<PowerAuthTimeSynchronizationService, PA2GetSystemStatusTaskDelegate>

/// Initialize time synchronization service.
/// - Parameters:
///   - coreService: Low level time synchronization service.
///   - sharedLock: Shared lock with recursive locking capability.
- (instancetype) initWithCoreService:(PowerAuthCoreTimeService*)coreService
                          httpClient:(PA2CoreHttpClient*)httpClient
                          sharedLock:(id<NSLocking>)sharedLock;

/// Subscribe for the system notifications. The service is using UIApplicationWillEnterForegroundNotification to
/// reset synchronization with the server.
- (void) subscribeForSystemNotifications;

/// Unsubscribe from previously subscribed system notifications.
- (void) unsubscribeForSystemNotifications;

/// Fetch status from the server.
/// - Parameter callback: Callback called once the status is received.
/// - Parameter callbackQueue: Queue where callback will be reported.
/// - Returns: Task representing asynchronous operation.
- (id<PowerAuthOperationTask>) fetchServerStatus:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
                                   callbackQueue:(dispatch_queue_t)callbackQueue;

/// Cancels all pending operations.
- (void) cancelAllPendingRequests;

@end
