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

#import <PowerAuth2/PowerAuthOperationTask.h>

/// The `PowerAuthTimeSynchronizationService` protocol defines interface that allows you to synchronize the
/// local device time with the PowerAuth Server and then get the synchronized time.
@protocol PowerAuthTimeSynchronizationService <NSObject>
@required

/// Contains information whether the service has its time synchronized with the server.
@property (nonatomic, readonly) BOOL isTimeSynchronized;

/// Contains calculated local time difference against the server. The value of the property
/// is informational and is provided only for the testing or the debugging purposes.
@property (nonatomic, readonly) NSTimeInterval localTimeAdjustment;

/// Contains value representing a maximum absolute deviation of synchronized time against the actual time on the server.
/// Depending on this value you can determine whether this deviation is within your expected margins. If the current
/// synchronized time is out of your expectations, then try to synchronize the time again.
@property (nonatomic, readonly) NSTimeInterval localTimeAdjustmentPrecision;

/// Return the current local time synchronized with the server. The returned value is in the seconds since the
/// reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
/// the current local time (e.g. `Date().timeIntervalSince1970`.) You can test `isTimeSynchronized` property if
/// this is not sufficient for your purposes.
- (NSTimeInterval) currentTime;

/// Synchronize the local with the time on the server.
/// - Parameter callback: Callback called once the synchronization task is complete. If the error parameter is `nil` then everything's OK.
/// - Parameter callbackQueue: Queue for completion callback execution. If nil, then the main dispatch queue is used.
/// - Returns: Task associated with the running HTTP request or nil in case that PowerAuthSDK instance is no longer valid.
- (nullable id<PowerAuthOperationTask>) synchronizeTimeWithCallback:(void (^_Nonnull)(NSError * _Nullable error))callback
                                                      callbackQueue:(dispatch_queue_t _Nullable)callbackQueue;

/// Reset the time synchronization. The time must be synchronized again after this call.
- (void) resetTimeSynchronization;

@end
