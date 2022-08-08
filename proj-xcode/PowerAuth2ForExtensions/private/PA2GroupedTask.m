/*
 * Copyright 2022 Wultra s.r.o.
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2GroupedTask.h"
#import "PA2PrivateMacros.h"
#import <PowerAuth2ForExtensions/PowerAuthLog.h>

#pragma mark - Grouped task

#define FINISH_AUTO_CANCEL      0x001
#define FINISH_SET_CANCEL       0x010

@implementation PA2GroupedTask
{
    NSMutableArray<PA2ChildTask*> * _childTasks;
    NSMutableArray<id<PowerAuthOperationTask>> * _operations;
    NSString * _taskName;
    BOOL _started;
    BOOL _finished;
    BOOL _canceled;
}

- (nonnull instancetype) init
{
    return [self initWithSharedLock:[[NSRecursiveLock alloc] init] taskName:nil];
}

- (nonnull instancetype) initWithSharedLock:(nonnull id<NSLocking>)sharedLock
                                   taskName:(nullable NSString*)taskName
{
    self = [super init];
    if (self) {
        _lock = sharedLock;
        _childTasks = [NSMutableArray arrayWithCapacity:1];
        _operations = [NSMutableArray arrayWithCapacity:1];
        _taskName = taskName ? taskName : [self.class description];
        _finished = NO;
    }
    return self;
}

- (BOOL) restart
{
    [_lock lock];
    //
    BOOL result = !_started || _finished;
    if (result) {
        // Task can be restarted only if it's not started or it's already finished.
        _started = NO;
        _finished = NO;
        _canceled = NO;
        [_childTasks removeAllObjects];
        [_operations removeAllObjects];
        [self onTaskRestart];
    }
    
    [_lock unlock];
    //
    return result;
}

- (PA2ChildTask *) createChildTask:(void (^)(id _Nullable, NSError * _Nullable))completion
{
    [_lock lock];
    //
    PA2ChildTask * result;
    if (!_finished) {
        result = [[PA2ChildTask alloc] initWithParentTask:self completion:completion];
        [_childTasks addObject:result];
        if (!_started && _childTasks.count == 1) {
            _started = YES;
            [self onTaskStart];
            // Print warning if implementation did not assing internal operation.
            if (_operations.count == 0) {
                // The task implementation failed to add a cancelable operation.
                PowerAuthLog(@"%@: No operation is registered after task start.", _taskName);
                NSError * error = PA2MakeError(PowerAuthErrorCode_OperationCancelled, @"Internal error. No operation is set");
                [self finishTask:nil error:error withFlags:FINISH_SET_CANCEL];
            }
        }
    } else {
        PowerAuthLog(@"%@: Task is already finished", _taskName);
        result = nil;
    }
    //
    [_lock unlock];
    return result;
}

- (void) removeChildTask:(id<PowerAuthOperationTask>)operation
{
    void(^cleanupJobs)(void) = nil;
    
    [_lock lock];
    //
    [_childTasks removeObject:operation];
    if (_childTasks.count == 0 && !_finished) {
        if ([self shouldCancelWhenNoChildOperationIsSet]) {
            cleanupJobs = [self finishTask:nil error:nil withFlags:FINISH_AUTO_CANCEL];
        } else {
            PowerAuthLog(@"%@: Task is going to complete itself whith no child set.", _taskName);
        }
    }
    //
    [_lock unlock];
    
    if (cleanupJobs) {
        cleanupJobs();
    }
}

- (void) complete:(id)result error:(NSError *)error
{
    [_lock lock];
    //
    void(^cleanupJobs)(void) = [self finishTask:result error:error withFlags:0];
    //
    [_lock unlock];
    if (cleanupJobs) {
        cleanupJobs();
    }
}

- (BOOL) addCancelableOperation:(id<PowerAuthOperationTask>)cancelable
{
    [_lock lock];
    //
    BOOL result = !_finished;
    if (result) {
        [_operations addObject:cancelable];
    }
    //
    [_lock unlock];
    return result;
}

- (BOOL) replaceCancelableOperation:(id<PowerAuthOperationTask>)cancelable
{
    [_lock lock];
    //
    BOOL result = !_finished;
    if (result) {
        if (_operations.count == 1) {
            [_operations removeLastObject];
        }
        [_operations addObject:cancelable];
    }
    //
    [_lock unlock];
    return result;
}

#pragma mark Overridable

- (void) onTaskStart
{
    PowerAuthLog(@"%@: Task is starting.", _taskName);
}

- (void) onTaskRestart
{
    PowerAuthLog(@"%@: Task is restarted.", _taskName);
}

- (void) onTaskCompleteWithResult:(id)result error:(NSError*)error
{
    if (result && !error) {
        PowerAuthLog(@"%@: Task is complete with result.", _taskName);
    } else if (!result && error) {
        if (!_canceled) {
            PowerAuthLog(@"%@: Task is complete with error: %@", _taskName, error);
        } else {
            PowerAuthLog(@"%@: Task is complete with forced cancel.", _taskName);
        }
    } else {
        PowerAuthLog(@"%@: Task is complete with automatic cancel.", _taskName);
    }
}

- (BOOL) shouldCancelWhenNoChildOperationIsSet
{
    return YES;
}

#pragma mark PowerAuthOperationTask

- (void) cancel
{
    [_lock lock];
    //
    void(^cleanupJobs)(void) = [self finishTask:nil error:nil withFlags:FINISH_SET_CANCEL];
    //
    [_lock unlock];
    
    if (cleanupJobs) {
        cleanupJobs();
    }
}

- (BOOL) isCancelled
{
    [_lock lock];
    //
    BOOL result = _canceled;
    //
    [_lock unlock];
    return result;
}

#pragma mark Thread synchronization

- (void) synchronizedVoid:(void(NS_NOESCAPE ^)(void))block
{
    [_lock lock];
    //
    block();
    //
    [_lock unlock];
}

- (id) synchronized:(id (NS_NOESCAPE ^ )(void))block
{
    [_lock lock];
    //
    id result = block();
    [_lock unlock];
    //
    return result;
}

#pragma mark Private functions

/**
 Finish tash with result or error. Both error and result may be nil, but then the flags
 parameter must contain one of completion flags:
 - FINISH_AUTO_CANCEL, must be set if task is automatically canceled.   
 - FINISH_SET_CANCEL, must be set if task is force canceled.
 */
- (void(^)(void)) finishTask:(id)result error:(NSError*)error withFlags:(NSInteger)flags
{
    BOOL isAutoCancel   = (flags & FINISH_AUTO_CANCEL) != 0;
    BOOL isForcedCancel = (flags & FINISH_SET_CANCEL) != 0;
    
    NSArray<PA2ChildTask*> * childTasks;
    NSArray<id<PowerAuthOperationTask>> * operationsToCancel;
    if (!_finished) {
        _finished = YES;
        _canceled = isForcedCancel;
        if (isForcedCancel && !error) {
            error = PA2MakeError(PowerAuthErrorCode_OperationCancelled, nil);
        }
        childTasks = isAutoCancel ? nil : [_childTasks copy];
        operationsToCancel = isForcedCancel || isAutoCancel ? [_operations copy] : nil;
        
        [_childTasks removeAllObjects];
        [_operations removeAllObjects];
        
        [self onTaskCompleteWithResult:result error:error];
        
    } else {
        childTasks = nil;
        operationsToCancel = nil;
    }

    if (operationsToCancel || childTasks) {
        return ^{
            // Cancel all remaining pending operations
            [operationsToCancel enumerateObjectsUsingBlock:^(id<PowerAuthOperationTask> op, NSUInteger idx, BOOL * stop) {
                [op cancel];
            }];
            
            // Dispatch results back to child tasks
            if (childTasks) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [childTasks enumerateObjectsUsingBlock:^(PA2ChildTask* childTask, NSUInteger idx, BOOL * _Nonnull stop) {
                        [childTask complete:result error:error];
                    }];
                });
            }
        };
    }
    return nil;
}

@end

#pragma mark - Child task

@implementation PA2ChildTask
{
    __weak PA2GroupedTask * _parentTask;
    id<NSLocking> _lock;
    void(^_completion)(id result, NSError * error);
    BOOL _isCancelled;
}

- (instancetype) initWithParentTask:(PA2GroupedTask*)parentTask
                         completion:(void(^)(id result, NSError * error))completion
{
    self = [super init];
    if (self) {
        _parentTask = parentTask;
        _lock = parentTask.lock;
        _completion = completion;
    }
    return self;
}

- (void) complete:(id)result error:(NSError*)error
{
    [_lock lock];
    //
    if (!_isCancelled) {
        _isCancelled = YES;
        if (_completion) {
            _completion(result, error);
            _completion = nil;
        }
    }
    //
    [_lock unlock];
}

- (void) cancel
{
    [_lock lock];
    //
    if (!_isCancelled) {
        _isCancelled = YES;
        [_parentTask removeChildTask:self];
        _completion = nil;
    }
    //
    [_lock unlock];
}

- (BOOL) isCancelled
{
    [_lock lock];
    //
    BOOL result = _isCancelled;
    [_lock unlock];
    //
    return result;
}

@end
