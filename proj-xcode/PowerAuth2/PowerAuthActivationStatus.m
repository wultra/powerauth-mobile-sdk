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

#import "PowerAuthActivationStatus.h"
#import "PowerAuthActivationStatus+Private.h"

#import <PowerAuthCore/PowerAuthCore.h>

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

- (NSDate*) blockExpirationTime
{
    return _status.blockExpirationTime;
}

- (BOOL) isProtocolUpgradeAvailable
{
    return _status.isProtocolUpgradeAvailable;
}

- (NSDictionary<NSString*, NSObject*>*) customObject
{
    return _status.customObject;
}

- (NSString*) description
{
    NSString * state;
    switch (_status.state) {
        case PowerAuthCoreActivationState_Active:       state = @"active"; break;
        case PowerAuthCoreActivationState_Blocked:      state = @"blocked"; break;
        case PowerAuthCoreActivationState_Removed:      state = @"removed"; break;
        case PowerAuthCoreActivationState_PendingCommit:state = @"pendingCommit"; break;
        case PowerAuthCoreActivationState_Deadlock:     state = @"deadlock"; break;
        default:
            state = @"???";
            break;
    }
    NSString * upgrade = _status.isProtocolUpgradeAvailable ? @", upgradeAvail" : @"";
    return [NSString stringWithFormat:@"<PowerAuthActivationStatus state=%@, remaining=%@/%@%@>",
            state, @(_status.remainingAttempts), @(_status.maxFailCount), upgrade];
}

@end

@implementation PowerAuthActivationStatus (Private)

- (instancetype) initWithCoreStatus:(PowerAuthCoreActivationStatus *)status
{
    self = [super init];
    if (self) {
        _status = status;
    }
    return self;
}

@end
