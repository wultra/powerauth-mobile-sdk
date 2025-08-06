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

#include <PowerAuth/TimeService.h>

#import <PowerAuthCore/PowerAuthCoreTimeService.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace powerAuth;
using namespace cc7;

@implementation PowerAuthCoreTimeService
{
    TimeServicePtr _time_service;
}

- (instancetype) initWithService:(const TimeServicePtr&)timeService
{
    self = [super init];
    if (self) {
        _time_service = timeService;
    }
    return self;
}

- (BOOL) isTimeSynchronized
{
    return _time_service->isTimeSynchronized();
}

- (NSTimeInterval) currentTime
{
    return _time_service->currentTime();
}

- (NSTimeInterval) localTimeAdjustment
{
    return _time_service->localTimeAdjustment();
}

- (NSTimeInterval) localTimeAdjustmentPrecision
{
    return _time_service->localTimeAdjustmentPrecision();
}

- (nullable PowerAuthCoreRequest*) createTimeSynchronizationRequest:(NSError*_Nullable*_Nullable)error
{
    try {
        auto request = _time_service->createTimeSynchronizationRequest();
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (BOOL) hasPendingTimeSynchronizationRequest
{
    return _time_service->hasPendingSynchronizationRequest();
}

- (void) resetTimeSynchronization
{
    try {
        _time_service->resetTimeSynchronization();
    } catch (...) {
        PowerAuthCoreLog(@"TimeService.resetTimeSynchronization failed: %@", BuildNSErrorFromException());
    }
}

@end
