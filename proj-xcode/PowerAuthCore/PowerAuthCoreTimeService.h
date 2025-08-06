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
#import <PowerAuthCore/PowerAuthCoreRequest.h>

/// The `PowerAuthCoreTimeService` protocol provides functionality for getting
/// time synchronized with the server and allows synchronize time with the server.
@interface PowerAuthCoreTimeService : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains information whether the service has its time synchronized with the server.
@property (nonatomic, readonly) BOOL isTimeSynchronized;

/// Return the current local time synchronized with the server. The returned value is in the seconds since the
/// reference date 1.1.1970 (e.g. unix timestamp.) If the local time is not synchronized, then returns
/// the current local time (e.g. `Date().timeIntervalSince1970`.) You can test `isTimeSynchronized` property if
/// this is not sufficient for your purposes.
@property (nonatomic, readonly) NSTimeInterval currentTime;

/// Return calculated local time difference against the server. The value  is informational and is provided only
/// for the testing or the debugging purposes.
@property (nonatomic, readonly) NSTimeInterval localTimeAdjustment;

/// Return value representing a maximum absolute deviation of synchronized time against the actual time on the server.
/// Depending on this value you can determine whether this deviation is within your expected margins. If the current
/// synchronized time is out of your expectations, then try to synchronize the time again.
@property (nonatomic, readonly) NSTimeInterval localTimeAdjustmentPrecision;

/// Creates HTTP request for time synchronization.
/// - Parameter error: Pointer where the error will be stored in case of failure.
/// - Returns: HTTP request or `nil` in case of failure.
- (nullable PowerAuthCoreRequest*) createTimeSynchronizationRequest:(NSError*_Nullable*_Nullable)error;

/// Get information whether there's already pending request for time synchronization.
/// - Returns: YES in there's pending request for time synchronization.
- (BOOL) hasPendingTimeSynchronizationRequest;

/// Reset time synchronization.
- (void) resetTimeSynchronization;

@end

