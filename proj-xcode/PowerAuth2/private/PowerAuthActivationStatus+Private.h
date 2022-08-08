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

#import <PowerAuth2/PowerAuthActivationStatus.h>

@class PowerAuthCoreActivationStatus;

// Reveal private interface for PowerAuthCoreActivationStatus object.

@interface PowerAuthActivationStatus (Private)
/**
 Private constructor with core status object and optional custom object
 */
- (instancetype) initWithCoreStatus:(PowerAuthCoreActivationStatus*)status
                       customObject:(NSDictionary<NSString*, NSObject*>*)customObject;
/**
 Contains current version of activation
 */
@property (nonatomic, assign, readonly) UInt8 currentActivationVersion;
/**
 Contains version of activation available for upgrade.
 */
@property (nonatomic, assign, readonly) UInt8 upgradeActivationVersion;
/**
 Contains YES if upgrade to a newer protocol version is available.
 */
@property (nonatomic, assign, readonly) BOOL isProtocolUpgradeAvailable;
/**
 Returns true if dummy signature calculation is recommended to prevent
 the counter's de-synchronization.
 */
@property (nonatomic, assign, readonly) BOOL isSignatureCalculationRecommended;
/**
 Returns true if session's state should be serialized after the successful
 activation status decryption.
 */
@property (nonatomic, assign, readonly) BOOL needsSerializeSessionState;

@end
