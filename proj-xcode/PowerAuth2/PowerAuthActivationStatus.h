/*
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

#import <PowerAuth2/PowerAuthMacros.h>

/**
 The PowerAuthActivationState enum defines all possible states of activation.
 The state is a part of information received together with the rest
 of the PowerAuthActivationStatus object.
 */
typedef NS_ENUM(NSInteger, PowerAuthActivationState) {
	/**
	 The activation is just created.
	 */
	PowerAuthActivationState_Created  = 1,
	/**
	 The activation is not completed yet on the server.
	 */
	PowerAuthActivationState_PendingCommit = 2,
	/**
	 The shared secure context is valid and active.
	 */
	PowerAuthActivationState_Active   = 3,
	/**
	 The activation is blocked.
	 */
	PowerAuthActivationState_Blocked  = 4,
	/**
	 The activation doesn't exist anymore.
	 */
	PowerAuthActivationState_Removed  = 5,
	/**
	 The activation is technically blocked. You cannot use it anymore
	 for the signature calculations.
	 */
	PowerAuthActivationState_Deadlock	= 128,
};

/**
 The PowerAuthActivationStatus object represents complete status of the activation.
 The status is typically received as an encrypted blob and you can use module
 to decode that blob into this object.
 */
@interface PowerAuthActivationStatus : NSObject

/**
 State of the activation
 */
@property (nonatomic, assign, readonly) PowerAuthActivationState state;
/**
 Number of failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 failCount;
/**
 Maximum number of allowed failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 maxFailCount;
/**
 Contains (maxFailCount - failCount) if state is `PowerAuthActivationState_Active`,
 otherwise 0.
 */
@property (nonatomic, assign, readonly) UInt32 remainingAttempts;

@end

