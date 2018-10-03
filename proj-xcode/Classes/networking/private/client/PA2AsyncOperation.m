/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2AsyncOperation.h"
#import "PA2Log.h"


@interface PA2AsyncOperation (Private)
@property (nonatomic, assign) BOOL isExecuting;
@property (nonatomic, assign) BOOL isFinished;
@end


@implementation PA2AsyncOperation
{
	BOOL _reported;
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
		_reported = NO;
		_isExecuting = NO;
		_isFinished = NO;
		_reportQueue = queue;
		_lock = [[NSLock alloc] init];
	}
	return self;
}


#pragma mark - main & cancel

- (void) main
{
	self.isExecuting = YES;
	
	// In first lock, we need to acquire execution block and set marker
	// that we're in the execution block.
	
	[_lock lock];
	//
	_inExecutionBlock = YES;
	id (^execution)(PA2AsyncOperation*) = _executionBlock;
	_executionBlock = nil;
	//
	[_lock unlock];
	
	if (execution) {
		// Call execution block & acquire operation task
		id operationTask = execution(self);
		
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
		if (self.isCancelled) {
			[self cancelImpl];
		}
		//
		[_lock unlock];
		//
	} else {
		PA2Log(@"WARNING: Internal: Async queue without an execution block.");
		self.isExecuting = NO;
		self.isFinished = YES;
		[self completeWithResult:nil error:nil];
	}
	
}

- (void) cancel
{
	[super cancel];
	[_lock lock];
	//
	[self cancelImpl];
	//
	[_lock unlock];
}

- (void) cancelImpl
{
	if (!_inExecutionBlock) {
		if (_cancelBlock) {
			_cancelBlock(self, _operationTask);
			_cancelBlock = nil;
		}
		_operationTask = nil;
	}
}


#pragma mark - Completion

- (void) completeWithResult:(id)result error:(NSError*)error
{
	self.isExecuting = NO;
	self.isFinished = YES;
	
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

- (void) setIsExecuting:(BOOL)value
{
	[self willChangeValueForKey:@"isExecuting"];
	_isExecuting = value;
	[self didChangeValueForKey:@"isExecuting"];
}

- (BOOL) isExecuting
{
	return _isExecuting;
}

- (void) setIsFinished:(BOOL)value
{
	[self willChangeValueForKey:@"isFinished"];
	_isFinished = value;
	[self didChangeValueForKey:@"isFinished"];
}

- (BOOL) isFinished
{
	return _isFinished;
}

@end
