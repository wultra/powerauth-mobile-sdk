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

#import "PA2GetSystemStatusTask.h"

@import PowerAuthCore;

/// The `PA2TimeSynchronizationService` class provides functionality to synchronize time with the server.
/// The class implements both `PowerAuthTimeSynchronizationService` and `PowerAuthCoreTimeService` protocols.
@interface PA2TimeSynchronizationService : NSObject<PowerAuthTimeSynchronizationService, PowerAuthCoreTimeService>

/// Initialize time synchronization service.
/// - Parameters:
///   - statusProvider: Object providing system status from the server.
///   - sharedLock: Shared lock with recursive locking capability.
- (instancetype) initWithStatusProvider:(id<PA2SystemStatusProvider>)statusProvider
                             sharedLock:(id<NSLocking>)sharedLock;

/// Subscribe for the system notifications. The service is using UIApplicationWillEnterForegroundNotification to
/// reset synchronization with the server.
- (void) subscribeForSystemNotifications;

/// Unsubscribe from previously subscribed system notifications.
- (void) unsubscribeForSystemNotifications;

#ifdef DEBUG
/// Configure internal time provider to a custom function for testing purposes.
/// - Parameter timeProviderFunc: Time provider or nil to set back to default.
- (void) setTestTimeProvider:(NSTimeInterval (*)(void))timeProviderFunc;
#endif

@end
