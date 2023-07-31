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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

/// The `PowerAuthCoreTimeService` class provides time synchronization with the server.
/// However, the class itself does not handle communication with the PowerAuth server
/// to achieve this synchronization. Instead, you must use your own code in conjunction
/// with the `startTimeSynchronizationTask` and `completeTimeSynchronizationTask` methods.
///
/// The synchronization status is reset whenever the application transitions from the background
/// to the foreground. The shared instance of the service listens
/// for `UIApplicationWillEnterForegroundNotification` to manage this.
@interface PowerAuthCoreTimeService : NSObject

/// Contains shared instance of this class.
@property (class, nonatomic, readonly, strong) PowerAuthCoreTimeService * sharedInstance;

/// Contains information whether the service has its time synchronized with the server.
@property (nonatomic, readonly) BOOL isTimeSynchronized;

/// Contains calculated local time difference against the server. The value of the property
/// is informational and is provided only for the testing or the debugging purposes.
@property (nonatomic, readonly) NSTimeInterval localTimeAdjustment;

/// Return the current local time synchronized with the server. The returned value is in the seconds since the
/// reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
/// the current local time (e.g. `Date().timeIntervalSince1970`.) You can test `isTimeSynchronized` property if
/// this is not sufficient for your purposes.
- (NSTimeInterval) currentTime;

/// Start time synchronization task and return object representing such task. The same object must be later
/// provided to `completeTimeSynchronizationTask:withServerTime:` function.
- (id) startTimeSynchronizationTask;

/// Complete the time synchronization task with time received from the server.
/// - Parameters:
///   - task: Task object created in `startTimeSynchronizationTask` function.
///   - serverTime: Timestamp received from the server with the milliseconds' precision.
/// - Returns: YES if the server time has been processed and time is now synchronized.
- (BOOL) completeTimeSynchronizationTask:(id)task withServerTime:(NSTimeInterval)serverTime;

/// Reset the time synchronization. The time must be synchronized again after this call.
- (void) resetTimeSynchronization;

@end

