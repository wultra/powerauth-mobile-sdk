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

#import "PA2CompositeTask.h"

@implementation PA2CompositeTask
{
    dispatch_semaphore_t _lock;
    BOOL _isCancelled;
    BOOL _isCompleted;
    id<PowerAuthOperationTask> _operationTask;
    void(^_cancelBlock)(void);
}

#define LOCK()      dispatch_semaphore_wait(_lock, DISPATCH_TIME_FOREVER)
#define UNLOCK()    dispatch_semaphore_signal(_lock)

- (instancetype) initWithCancelBlock:(void(^)(void))cancelBlock
{
    self = [super init];
    if (self) {
        _lock = dispatch_semaphore_create(1);
        _cancelBlock = cancelBlock;
    }
    return self;
}

- (BOOL) isCancelled
{
    LOCK();
    //
    BOOL result = _isCancelled;
    //
    UNLOCK();
    return result;
}

- (BOOL) isNotFinished
{
    return !(_isCancelled || _isCompleted);
}

- (void) cancel
{
    void(^cancelBlock)(void) = nil;
    
    LOCK();
    //
    if ([self isNotFinished]) {
        _isCancelled = YES;
        [_operationTask cancel];
        _operationTask = nil;
        cancelBlock = _cancelBlock;
        _cancelBlock = nil;
    }
    //
    UNLOCK();
    
    // Execute cancel block from outside of the lock to prevent
    // a possible deadlock.
    if (cancelBlock) {
        cancelBlock();
    }
}

- (BOOL) replaceOperationTask:(id<PowerAuthOperationTask>)operationTask
{
    LOCK();
    //
    BOOL result = [self isNotFinished];
    if (result) {
        _operationTask = operationTask;
    } else {
        [operationTask cancel];
    }
    //
    UNLOCK();
    return result;
}

- (BOOL) setCompleted
{
    LOCK();
    //
    BOOL result = [self isNotFinished];
    _isCompleted = YES;
    _cancelBlock = nil;
    //
    UNLOCK();
    return result;
}

@end
