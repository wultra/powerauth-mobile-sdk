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
#import "PowerAuthActivationStatus+Private.h"

@import PowerAuthCore;

@implementation PowerAuthActivationStatus
{
    PowerAuthCoreActivationStatus * _Nonnull _status;
}

- (PowerAuthActivationState) state
{
    return (PowerAuthActivationState) _status.state;
}

- (UInt32) failCount
{
    return _status.failCount;
}

- (UInt32) maxFailCount
{
    return _status.maxFailCount;
}

- (UInt32) remainingAttempts
{
    return _status.remainingAttempts;
}

@end

@implementation PowerAuthActivationStatus (Private)

- (instancetype) initWithCoreStatus:(PowerAuthCoreActivationStatus *)status
                       customObject:(NSDictionary<NSString *,NSObject *> *)customObject
{
    self = [super init];
    if (self) {
        _status = status;
        _customObject = customObject;
    }
    return self;
}

- (UInt8) currentActivationVersion
{
    return _status.currentActivationVersion;
}

- (UInt8) upgradeActivationVersion
{
    return _status.upgradeActivationVersion;
}

- (BOOL) isProtocolUpgradeAvailable
{
    return _status.isProtocolUpgradeAvailable;
}

- (BOOL) isSignatureCalculationRecommended
{
    return _status.isSignatureCalculationRecommended;
}

- (BOOL) needsSerializeSessionState
{
    return _status.needsSerializeSessionState;
}

@end
