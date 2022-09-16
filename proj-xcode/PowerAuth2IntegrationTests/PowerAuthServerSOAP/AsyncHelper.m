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

#import "AsyncHelper.h"
#include <stdatomic.h>

@implementation AsyncHelper
{
    dispatch_semaphore_t _semaphore;
    BOOL _hasResult;
    id _result;
    NSDate * _startTime;
}

- (id) init
{
    self = [super init];
    if (self) {
        _semaphore = dispatch_semaphore_create(0);
        _result = nil;
        _hasResult = NO;
        _startTime = nil;
        if (_semaphore == NULL) {
            return nil;
        }
    }
    return self;
}

+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block
                               wait:(NSTimeInterval)interval
{
    if (!block) {
        return nil;
    }
    AsyncHelper * waiting = [[AsyncHelper alloc] init];
    if (!waiting) {
        @throw [NSException exceptionWithName:@"AsyncHelper" reason:@"Can't create synchronization semaphore" userInfo:nil];
        return nil;
    }
    block(waiting);
    return [waiting waitForCompletion:interval];
}

+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block
{
    return [self synchronizeAsynchronousBlock:block wait:10.0];
}

- (void) reportCompletion:(id)resultObject
{
    @synchronized (self) {
        if (!_hasResult) {
            _hasResult = YES;
            _result = resultObject;
        } else {
            @throw [NSException exceptionWithName:@"AsyncHelper" reason:@"Test already reported a result" userInfo:nil];
        }
    }
    dispatch_semaphore_signal(_semaphore);
}

- (id) waitForCompletion:(NSTimeInterval)waitingTime
{
    [self extendWaitingTime];
    long triggered = 0;
    while ([self shouldWait:waitingTime]) {
        // We need to prevent possible deadlocks, between our semaphore and the mesagess, processed in the runloop.
        // So, at first, we will try to process current runloop for a while and then, our semaphore will wait.
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        triggered = dispatch_semaphore_wait(_semaphore, dispatch_time(DISPATCH_TIME_NOW, 0.01*NSEC_PER_SEC));
        if (triggered == 0) {
            break;
        }
    }
    if (triggered != 0) {
        @throw [NSException exceptionWithName:@"AsyncHelper" reason:@"waitForCompletion timed out" userInfo:nil];
    }
    return _result;
}

- (BOOL) shouldWait:(NSTimeInterval)waitingTime
{
    @synchronized (self) {
        return [[NSDate date] timeIntervalSinceDate:_startTime] < waitingTime;
    }
}

- (void) extendWaitingTime
{
    @synchronized (self) {
        _startTime = [NSDate date];
    }
}

+ (void) waitForNextSecond
{
    NSTimeInterval nextSecondStart = (NSTimeInterval)((int64_t)[[NSDate date] timeIntervalSince1970] + 1L);
    [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSince1970:nextSecondStart]];
}

+ (void) waitForQueuesCompletion:(NSArray<NSOperationQueue*>*)queues
{
    AtomicCounter * ctr = [[AtomicCounter alloc] init];
    int32_t queuesCount = (int32_t)queues.count;
    [self synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
        [queues enumerateObjectsUsingBlock:^(NSOperationQueue * queue, NSUInteger idx, BOOL * stop) {
            NSLog(@"AsyncHelper: Waiting for queue %@", queue.name ? queue.name : @"<UNNAMED>");
            if (@available(iOS 13.0, tvOS 13.0, *)) {
                [queue addBarrierBlock:^{
                    [ctr incrementUpTo:queuesCount completion:^{
                        [waiting reportCompletion:nil];
                    }];
                }];
            } else {
                @throw [NSException exceptionWithName:@"AsyncHelper" reason:@"Unsupported platform for tests" userInfo:nil];
            }
        }];
    }];
    NSLog(@"AsyncHelper: All queues finished");
}

@end

@implementation AtomicCounter
{
    volatile atomic_int_fast32_t _value;
}

- (int32_t) value
{
    return _value;
}

- (int32_t) increment
{
    return atomic_fetch_add(&_value, 1) + 1;
}

- (int32_t) incrementUpTo:(int32_t)limit completion:(void (^)(void))block
{
    atomic_int_fast32_t next = atomic_fetch_add(&_value, 1) + 1;
    if (next >= limit) {
        block();
    }
    return next;
}

@end
