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

#import "PA2TimeSynchronizationService.h"
#import "PA2GetSystemStatusTask.h"
#import "PA2RestApiEndpoint.h"
#import "PA2PrivateMacros.h"
#import <PowerAuth2/PowerAuthLog.h>
#import <UIKit/UIApplication.h>

@implementation PA2TimeSynchronizationService
{
    dispatch_semaphore_t _lock;
    BOOL _receiveNotifications;
    BOOL _isTimeSynchronized;
    NSTimeInterval (*_timeProvider)(void);
    
    NSTimeInterval _localTimeAdjustment;
    NSTimeInterval _localTimeAdjustmentPrecision;
    
    __weak id<PA2SystemStatusProvider> _statusProvider;
}

/// Minimum time difference against the server accepted during the synchronization. If the difference
/// is less, then we consider the local time as synchronized.
#define MIN_ACCEPTED_TIME_DIFFERENCE 10.0

/// Minimum difference against the last time delta. This prevents the time fluctuation the time is synchronized.
/// For example, if the server is 100 seconds ahead, then we'll get differences like 100.1, 101, 99.8 and that might cause
/// a time fluctuation after each synchronization attempt. That means that the synchronized time may jump a little bit
/// back or forward after each synchronization attempt.
#define MIN_TIME_DIFFERENCE_DELTA     10.0

/// Maximum time for the request synchronization to complete.
/// In this setup we're adding maximum 8 seconds to the time returned from the server, so it's below our threshold
/// defined in `MIN_ACCEPTED_TIME_DIFFERENCE`. This guarantees that requests that take too long time will not affect
/// the time synchronization.
#define MAX_ACCEPTED_ELAPSED_TIME    16.0

// Default function providing system time.
static NSTimeInterval _Now(void)
{
    return [[NSDate date] timeIntervalSince1970];
}

- (instancetype) initWithStatusProvider:(id<PA2SystemStatusProvider>)statusProvider
                             sharedLock:(id<NSLocking>)sharedLock
{
    self = [super init];
    if (self) {
        _statusProvider = statusProvider;
        _lock = dispatch_semaphore_create(1);
        _timeProvider = _Now;
    }
    return self;
}

- (void) dealloc
{
    [self unsubscribeForSystemNotificationsImpl];
}

#ifdef DEBUG
- (void) setTestTimeProvider:(NSTimeInterval (*)(void))timeProviderFunc
{
    if (timeProviderFunc) {
        _timeProvider = timeProviderFunc;
    } else {
        _timeProvider = _Now;
    }
}
#endif // DEBUG

#pragma mark - PowerAuthTimeSynchronizationService protocol -

- (BOOL) isTimeSynchronized
{
    return [[self synchronized:^id{
        return @(self->_isTimeSynchronized);
    }] boolValue];
}

- (NSTimeInterval) localTimeAdjustment
{
    return [[self synchronized:^id{
        return @(self->_localTimeAdjustment);
    }] doubleValue];
}

- (NSTimeInterval) localTimeAdjustmentPrecision
{
    return [[self synchronized:^id{
        return @(self->_localTimeAdjustmentPrecision);
    }] doubleValue];
}

- (NSTimeInterval) currentTime
{
    return [[self synchronized:^id{
        return @(self->_timeProvider() + self->_localTimeAdjustment);
    }] doubleValue];
}

- (id) startTimeSynchronizationTask
{
    return @(self->_timeProvider());   // equal to [NSNumber initWithDouble:_Now()]
}

- (BOOL) completeTimeSynchronizationTask:(id)task withServerTime:(NSTimeInterval)serverTime
{
    if (![task isKindOfClass:[NSNumber class]]) {
        PowerAuthLog(@"PowerAuthTimeService: Wrong task object used for the commit.");
        return NO;  // Not a NSNumber object
    }
    if (strcmp("d", ((NSNumber*)task).objCType)) {
        PowerAuthLog(@"PowerAuthTimeService: Wrong task object used for the commit.");
        return NO;  // Not a double encoded in the number
    }
    return [[self synchronized:^id{
        NSTimeInterval now = self->_timeProvider();
        NSTimeInterval start = [task doubleValue];
        NSTimeInterval elapsedTime = now - start;
        if (elapsedTime < 0.0) {
            PowerAuthLog(@"PowerAuthTimeService: Wrong task object used for the commit.");
            return @NO;
        }
        if (elapsedTime > MAX_ACCEPTED_ELAPSED_TIME) {
            PowerAuthLog(@"PowerAuthTimeService: Synchronization request took too long to complete.");
            // Return the current synchronization status. We can be OK if the time was synchronized before.
            return @(self->_isTimeSynchronized);
        }
        NSTimeInterval timeDifferencePrecision = 0.5 * elapsedTime;
        NSTimeInterval adjustedServerTime = 0.001 * serverTime + timeDifferencePrecision; // serverTime/1000 + elapsedTime/2
        NSTimeInterval timeDifference = adjustedServerTime - now;
        BOOL adjustmentDeltaOK = fabs(self->_localTimeAdjustment - timeDifference) < MIN_TIME_DIFFERENCE_DELTA;
        if (fabs(timeDifference) < MIN_ACCEPTED_TIME_DIFFERENCE && adjustmentDeltaOK) {
            // Time difference is too low and delta against last adjustment is also within the range.
            // We can ignore it and mark time as synchronized.
            self->_isTimeSynchronized = YES;
            return @YES;
        }
        if (self->_isTimeSynchronized && adjustmentDeltaOK) {
            // The time adjustment is too low against the last calculated adjustment. This test prevents
            // the adjusted time fluctuation after each synchronization.
            return @YES;
        }
        // Keep local time adjustment and mark time as synchronized.
        self->_localTimeAdjustment = timeDifference;
        self->_isTimeSynchronized = YES;
        self->_localTimeAdjustmentPrecision = timeDifferencePrecision;
        return @YES;
    }] boolValue];
}

- (id) synchronized:(id(^)(void))block
{
    dispatch_semaphore_wait(_lock, DISPATCH_TIME_FOREVER);
    id result = block();
    dispatch_semaphore_signal(_lock);
    return result;
}

- (void) resetTimeSynchronization
{
    [self resetTimeSynchronizationImpl:NO];
}

- (void) resetTimeSynchronizationImpl:(BOOL)fromNotification
{
    [self synchronized:^id{
        if (!fromNotification || _receiveNotifications) {
            self->_isTimeSynchronized = NO;
            self->_localTimeAdjustment = 0.0;
            self->_localTimeAdjustmentPrecision = 0.0;
        }
        return nil;
    }];
}

- (id<PowerAuthOperationTask>) synchronizeTime:(void (^)(NSError *))completion
                               completionQueue:(dispatch_queue_t)completionQueue
{
    if (completionQueue == nil) {
        completionQueue = dispatch_get_main_queue();
    }
    if (self.isTimeSynchronized) {
        dispatch_async(completionQueue, ^{
            completion(nil);
        });
        return nil;
    }
    
    id<PA2SystemStatusProvider> provider = _statusProvider;
    if (!provider) {
        dispatch_async(completionQueue, ^{
            completion(PA2MakeError(PowerAuthErrorCode_OperationCancelled, @"PA2SystemStatusProvider instance is no longer valid"));
        });
        return nil;
    }
    id timeSynchronizationTask = [self startTimeSynchronizationTask];
    return [provider getSystemStatusWithCallback:^(PowerAuthServerStatus *status, NSError *error) {
        if (status && !error) {
            if (![self completeTimeSynchronizationTask:timeSynchronizationTask withServerTime:[status.serverTime timeIntervalSince1970]]) {
                error = PA2MakeError(PowerAuthErrorCode_TimeSynchronization, nil);
            }
        }
        completion(error);
    } callbackQueue:completionQueue];
}


#pragma mark - Notifications -

- (void) subscribeForSystemNotifications
{
    [self synchronized:^id{
        if (!_receiveNotifications) {
            _receiveNotifications = YES;
            // Register this instance for system notifications
            [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(willEnterForeground:) name:UIApplicationWillEnterForegroundNotification object:nil];
        }
        return nil;
    }];
}

- (void) unsubscribeForSystemNotifications
{
    [self synchronized:^id{
        [self unsubscribeForSystemNotificationsImpl];
        return nil;
    }];
}

- (void) unsubscribeForSystemNotificationsImpl
{
    if (_receiveNotifications) {
        _receiveNotifications = NO;
        [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationWillEnterForegroundNotification object:nil];
    }
}

- (void) willEnterForeground:(id)sender
{
    [self resetTimeSynchronizationImpl:YES];
}

@end
