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

#import <PA2AsyncOperation.h>
#import <PA2PrivateMacros.h>
#import <PowerAuth2/PowerAuthLog.h>

@interface PA2AsyncOperation (Private)
@property (nonatomic, assign) BOOL isExecuting;
@property (nonatomic, assign) BOOL isFinished;
@end


@implementation PA2AsyncOperation
{
    BOOL _reported;
    BOOL _isCanceled;
    BOOL _isExecuting;
    BOOL _isFinished;
    BOOL _inExecutionBlock;
    dispatch_queue_t _reportQueue;
    id<NSLocking> _lock;
}

- (id) initWithReportQueue:(dispatch_queue_t)queue
{
    self = [super init];
    if (self) {
        _reportQueue = queue;
        _lock = [[NSRecursiveLock alloc] init];
    }
    return self;
}


#pragma mark - start & cancel

- (void) start
{
    // In first lock, we need to acquire execution block and set marker
    // that we're in the execution block.

    [_lock lock];
    
    [self notifyStart];

    _inExecutionBlock = YES;
    id (^execution)(PA2AsyncOperation*) = _executionBlock;
    _executionBlock = nil;
    BOOL shouldExecuteBlock = _isCanceled == NO;
    //
    [_lock unlock];
    
    if (execution != nil) {
        // Call execution block & acquire operation task. If the operation
        // is already canceled, then do nothing.
        id operationTask = shouldExecuteBlock ? execution(self) : nil;
        
        // In second lock, we need to test, whether there was a cancel while we were
        // in the execution block. If yes, then the internal cancel needs to be called
        // again, because it was ignored during the actual cancel.
        //
        // This complex processing is trying to prevent a possible race between
        // execution & cancel blocks when cancel can be called during the execution,
        // but the operation task is not yet prepared.
        
        [_lock lock];
        //
        _inExecutionBlock = NO;
        _operationTask = operationTask;
        if (_isCanceled) {
            [self cancelImpl];
        }
        //
        [_lock unlock];
        //
    } else {
        PowerAuthLog(@"WARNING: Internal: Async operation without an execution block.");
        NSError * error = PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Async operation without an execution block.");
        [self completeWithResult:nil error:error];
    }
    
}

- (void) cancel
{
    [_lock lock];
    //
    [self cancelImpl];
    //
    [_lock unlock];
}

- (void) cancelImpl
{
    _isCanceled = YES;
    if (!_inExecutionBlock) {
        if (_cancelBlock) {
            _cancelBlock(self, _operationTask);
            _cancelBlock = nil;
        }
        _operationTask = nil;

        [self notifyStop];
    }
}

- (BOOL) isCancelled
{
    [_lock lock];
    //
    BOOL result = _isCanceled;
    //
    [_lock unlock];
    return result;
}


#pragma mark - Completion

- (void) completeWithResult:(id)result error:(NSError*)error
{
    [_lock lock];
    //
    [self notifyStop];
    _cancelBlock = nil;
    //
    [_lock unlock];
    
    dispatch_async(_reportQueue, ^{
        
        _operationResult = result;
        _operationError = error;
        
        // Call report block only if it's not cancelled and
        // if not already reported.
        if (!_reported && !self.isCancelled) {
            _reported = YES;
            if (_reportBlock) {
                _reportBlock(self);
                _reportBlock = nil;
            }
        }
    });
}


#pragma mark - NSOperation

- (BOOL) isAsynchronous
{
    return YES;
}

- (BOOL) isExecuting
{
    [_lock lock];
    BOOL result = _isExecuting;
    [_lock unlock];
    return result;
}

- (BOOL) isFinished
{
    [_lock lock];
    BOOL result = _isFinished;
    [_lock unlock];
    return result;
}

- (void) notifyStart
{
    [self willChangeValueForKey:@"isExecuting"];
    _isExecuting = YES;
    [self didChangeValueForKey:@"isExecuting"];
}

- (void) notifyStop
{
    if (_isExecuting) {
        [self willChangeValueForKey:@"isExecuting"];
        [self willChangeValueForKey:@"isFinished"];
        _isExecuting = NO;
        _isFinished = YES;
        [self didChangeValueForKey:@"isExecuting"];
        [self didChangeValueForKey:@"isFinished"];
    }
}

@end
