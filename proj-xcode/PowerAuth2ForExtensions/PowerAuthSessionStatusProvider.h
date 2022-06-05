/**
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 The `PowerAuthSessionStatusProvider` protocol defines an abstract interface for getting instant
 information about PowerAuth session.
 */
@protocol PowerAuthSessionStatusProvider <NSObject>
@required
/**
 Check if it is possible to start an activation process
 
 @return YES if activation process can be started, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) canStartActivation;

/**
 Checks if there is a pending activation (activation in progress).
 
 @return YES if there is a pending activation, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) hasPendingActivation;

/**
 Checks if there is a valid activation.
 
 @return YES if there is a valid activation, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) hasValidActivation;

/**
 Checks if there's a valid activation that requires a protocol upgrade. Contains NO once the upgrade
 process is started. The application should fetch the activation's status to do the upgrade.
 
 @return YES if there is available protocol upgrade.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) hasProtocolUpgradeAvailable;

/**
 Checks if there is a pending protocol upgrade.

 @return YES if session has a pending upgrade.
 */
- (BOOL) hasPendingProtocolUpgrade;

/**
 Read only property contains activation identifier or nil if object has no valid activation.
 */
@property (nonatomic, strong, nullable, readonly) NSString *activationIdentifier;

@end
