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


#import "PowerAuthCoreActivationStatus.h"
#include <PowerAuth/ActivationStatus.h>
#include <cc7/objc/ObjcJson.h>

@implementation PowerAuthCoreActivationStatus
{
    powerAuth::ActivationStatusPtr _status;
}

- (instancetype) initWithActivationStatus:(const powerAuth::ActivationStatusPtr&)status
{
    self = [super init];
    if (self) {
        _status = status;
        _customObject = cc7::objc::JsonValueToObjC(status->customObject());
    }
    return self;
}

- (PowerAuthCoreActivationState) state
{
    return static_cast<PowerAuthCoreActivationState>(_status->activationState());
}

- (UInt32) failCount
{
    return _status->failCount();
}

- (UInt32) maxFailCount
{
    return _status->maxFailCount();
}

- (UInt32) remainingAttempts
{
    return _status->remainingAttempts();
}

- (BOOL) isProtocolUpgradeAvailable
{
    return _status->isProtocolUpgradeAvailable();
}

- (BOOL) isCounterSynchronizationRecommended
{
    return _status->isCounterSynchronizationRecommended();
}

- (BOOL) isRemoveBiometricKekRecommended
{
    return _status->isRemoveBiometricKekRecommended();
}

- (BOOL) needsSerializeSessionState
{
    return _status->isSessionStateSerializationRecommended();
}

@end


@implementation PowerAuthCoreFetchActivationStatusData
@end
