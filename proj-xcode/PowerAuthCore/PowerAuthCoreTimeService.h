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

/// The `PowerAuthCoreTimeService` protocol provides functionality for getting
/// time synchronized with the server and allows synchronize time with the server.
@protocol PowerAuthCoreTimeService <NSObject>
@required

/// Contains information whether the service has its time synchronized with the server.
@property (nonatomic, readonly) BOOL isTimeSynchronized;

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
///   - serverTime: Timestamp received from the server.
/// - Returns: YES if the server time has been processed and time is now synchronized.
- (BOOL) completeTimeSynchronizationTask:(id)task withServerTime:(NSTimeInterval)serverTime;

@end

