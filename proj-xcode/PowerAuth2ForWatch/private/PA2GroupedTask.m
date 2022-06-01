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
#import <PowerAuth2ForWatch/PowerAuthLog.h>

#pragma mark - Grouped task

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
	return [self initWithSharedLock:[[NSRecursiveLock alloc] init]];
}

- (nonnull instancetype) initWithSharedLock:(nonnull id<NSLocking>)sharedLock
{
	self = [super init];
	if (self) {
		_lock = sharedLock;
		_childTasks = [NSMutableArray arrayWithCapacity:1];
		_operations = [NSMutableArray arrayWithCapacity:1];
		_taskName = [self.class description];
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
		PowerAuthLog(@"%@: Task is restarted.", _taskName);
		_started = NO;
		_finished = NO;
		_canceled = NO;
		[_childTasks removeAllObjects];
		[_operations removeAllObjects];
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
				PowerAuthLog(@"WARNING: %@: No operation is registered after task start.", _taskName);
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
	[_lock lock];
	//
	[_childTasks removeObject:operation];
	if (_childTasks.count == 0 && !_finished) {
		if ([self shouldCancelWhenNoChildOperationIsSet]) {
			[self onTaskCancel];
		} else {
			PowerAuthLog(@"%@: Task is going to complete itself whith no child set.", _taskName);
		}
	}
	//
	[_lock unlock];
}

- (void) complete:(id)result error:(NSError *)error
{
	[_lock lock];
	//
	NSArray * childTasks;
	if (!_finished) {
		_finished = YES;
		childTasks = [_childTasks copy];
		[_childTasks removeAllObjects];
		[_operations removeAllObjects];
		[self onTaskComplete];
	} else {
		childTasks = nil;
	}
	//
	[_lock unlock];
	
	[self dispatchResult:result error:error toChildTasks:childTasks];
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

- (void) onTaskStart
{
	PowerAuthLog(@"%@: Task is starting.", _taskName);
}

- (void) onTaskComplete
{
	PowerAuthLog(@"%@: Task is complete.", _taskName);
}

- (void) onTaskCancel
{
	PowerAuthLog(@"%@: Task is complete with automatic cancel.", _taskName);
	[self cancelTaskAndReportErrorToChilds:NO];
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
	if (!_canceled && !_finished) {
		_canceled = YES;
		// This is explicit cancel initiated from the SDK internals, so we should
		// report error back to app.
		PowerAuthLog(@"%@: Task is canceled from elsewhere.", _taskName);
		[self cancelTaskAndReportErrorToChilds:YES];
	}
	//
	[_lock unlock];
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

#pragma mark Private functions

/**
 Function dispatch result or error to the list of child tasks. The completion is performed from the main thread.
 */
- (void) dispatchResult:(id)result error:(NSError*)error toChildTasks:(NSArray<PA2ChildTask*>*)childTasks
{
	if (childTasks) {
		// Report result from the main thread.
		dispatch_async(dispatch_get_main_queue(), ^{
			[childTasks enumerateObjectsUsingBlock:^(PA2ChildTask* childTask, NSUInteger idx, BOOL * _Nonnull stop) {
				[childTask complete:result error:error];
			}];
		});
	}
}

- (void) cancelTaskAndReportErrorToChilds:(BOOL)reportError
{
	[_lock lock];
	//
	NSArray * operationsToCancel = nil;
	NSArray * childTasksToComplete = nil;
	if (!_finished) {
		_finished = YES;
		operationsToCancel = [_operations copy];
		if (reportError) {
			childTasksToComplete = [_childTasks copy];
			[_childTasks removeAllObjects];
		}
	}
	//
	[_lock unlock];
	
	[operationsToCancel enumerateObjectsUsingBlock:^(id<PowerAuthOperationTask> obj, NSUInteger idx, BOOL * _Nonnull stop) {
		[obj cancel];
	}];
	if (childTasksToComplete) {
		NSError * error = PA2MakeError(PowerAuthErrorCode_OperationCancelled, nil);
		[self dispatchResult:nil error:error toChildTasks:childTasksToComplete];
	}
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
