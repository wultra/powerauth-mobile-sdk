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

#import "PowerAuthMacros.h"

/**
 The `PowerAuthProtocolUpgradeResult` object represents result of the protocol upgrade task.
 */
@interface PowerAuthProtocolUpgradeResult : NSObject

/**
 Default construction is unavailable
 */
- (nonnull instancetype) init NS_UNAVAILABLE;

/**
 Indicates whether activation status fetch is required to complete the protocol upgrade.
 If this property is `YES`, `fetchActivationStatus` must be called to finish the protocol upgrade process.
 If this property is `NO`, no further action is required.
 */
@property (nonatomic, assign, readonly) BOOL activationStatusFetchRequired;

/**
 Decimalized fingerprint calculated from device and server public keys.
 The value is not present, if the protocol upgrade is not yet finished,
 i.e. the `activationStatusFetchRequired`field is set to `YES`.
 */
@property (nonatomic, strong, readonly, nullable) NSString * activationFingerprint;

@end
