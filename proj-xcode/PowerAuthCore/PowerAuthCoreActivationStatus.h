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

#import <Foundation/Foundation.h>

/// The `PowerAuthCoreActivationState` enum defines all possible states of activation.
/// The state is a part of information received together with the rest
/// of the PowerAuthCoreActivationStatus object.
typedef NS_ENUM(int, PowerAuthCoreActivationState) {
    /// The activation is not completed yet on the server.
    PowerAuthCoreActivationState_PendingCommit = 0,
    /// The shared secure context is valid and active.
    PowerAuthCoreActivationState_Active   = 1,
    /// The activation is blocked.
    PowerAuthCoreActivationState_Blocked  = 2,
    /// The activation doesn't exist anymore.
    PowerAuthCoreActivationState_Removed  = 3,
    /// The activation is technically blocked. You cannot use it anymore
    /// for the authentication code calculations.
    PowerAuthCoreActivationState_Deadlock   = 4,
};

/// The `PowerAuthCoreActivationStatus` object represents complete status of the activation.
@interface PowerAuthCoreActivationStatus : NSObject

/// State of the activation
@property (nonatomic, assign, readonly) PowerAuthCoreActivationState state;
/// Number of failed authentication attempts in a row.
@property (nonatomic, assign, readonly) UInt32 failCount;
/// Maximum number of allowed failed authentication attempts in a row.
@property (nonatomic, assign, readonly) UInt32 maxFailCount;
/// Contains (maxFailCount - failCount) if state is `PowerAuthCoreActivationState_Active`,
/// otherwise `0`.
@property (nonatomic, assign, readonly) UInt32 remainingAttempts;

// SDK-private (application should not use such interface)

/// Contains YES if upgrade to a newer protocol version is available.
@property (nonatomic, assign, readonly) BOOL isProtocolUpgradeAvailable;
/// Returns YES if dummy authentication code calculation is recommended to prevent
/// the counter's de-synchronization.
@property (nonatomic, assign, readonly) BOOL isCounterSynchronizationRecommended;
/// Returns true if session's state should be serialized after the successful
/// activation status decryption.
@property (nonatomic, assign, readonly) BOOL needsSerializeSessionState;


///  Contains custom object returned from the server. The value is optional and PowerAuth Application Server
/// must support this custom object.
@property (nonatomic, strong, nullable, readonly) NSDictionary<NSString*, NSObject*>* customObject;

@end
