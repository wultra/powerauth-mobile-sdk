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

#import <XCTest/XCTest.h>
#import <PowerAuth2/PowerAuth2.h>
#import "PA2GroupedTask.h"
#import "AsyncHelper.h"

// MARK: - Helper classes

@interface TestOperationTask: NSObject<PowerAuthOperationTask>
@property (atomic, readonly) NSInteger monitorCancelCount;
@end

@interface TestGroupTask : PA2GroupedTask<NSNumber*>

// Config
@property (nonatomic, assign) BOOL cancelWhenNoChildOperationIsSet;
@property (nonatomic, strong) void (^onTaskStartBlock)(TestGroupTask* groupTask);
@property (nonatomic, weak) AsyncHelper * waiting;

// Monitors
@property (atomic, readonly) NSInteger monitorOnTaskStartCount;
@property (atomic, readonly) NSInteger monitorOnTaskRestartCount;
@property (atomic, readonly) NSInteger monitorOnTaskCompleteCount;

// Operations
@property (nonatomic, readonly) TestOperationTask* testOperation;

@end

// MARK: - Helper classes impl.

@implementation TestGroupTask
- (id) init
{
	self = [super init];
	if (self) {
		_cancelWhenNoChildOperationIsSet = YES;
	}
	return self;
}
- (void) onTaskStart
{
	[super onTaskStart];
	@synchronized (self) { _monitorOnTaskStartCount++; }
	if (_onTaskStartBlock) {
		_onTaskStartBlock(self);
	} else {
		_testOperation = [[TestOperationTask alloc] init];
		[self addCancelableOperation:_testOperation];
	}
}
- (void) onTaskRestart
{
	@synchronized (self) {
		_monitorOnTaskStartCount = 0;
		_monitorOnTaskCompleteCount = 0;
		_monitorOnTaskRestartCount++;
		_testOperation = nil;
	}
}
- (void) onTaskCompleteWithResult:(id)result error:(NSError *)error
{
	[super onTaskCompleteWithResult:result error:error];
	@synchronized (self) { _monitorOnTaskCompleteCount++; }
	[_waiting reportCompletion:nil];
}
- (BOOL) shouldCancelWhenNoChildOperationIsSet
{
	return _cancelWhenNoChildOperationIsSet;
}
@end

@implementation TestOperationTask
{
	BOOL _isCanceled;
}
- (BOOL) isCancelled
{
	return _isCanceled;
}
- (void) cancel
{
	@synchronized (self) {
		_isCanceled = YES;
		_monitorCancelCount++;
	}
}
@end



// MARK: - Test case

@interface PA2GroupedTaskTests : XCTestCase
@end

@implementation PA2GroupedTaskTests
{
	NSOperationQueue * _queue;
}

- (void) setUp
{
	PowerAuthLogSetEnabled(YES);
	_queue = [[NSOperationQueue alloc] init];
	_queue.maxConcurrentOperationCount = 4;
}

- (void) tearDown
{
	[_queue cancelAllOperations];
	[_queue waitUntilAllOperationsAreFinished];
}

- (void) testGroupedOperation
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	NSNumber * syncToken = [[NSNumber alloc] init];
	__block NSInteger completionCounter = 0;
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTAssertEqual(99, [result integerValue]);
			XCTAssertNil(error);
			@synchronized (syncToken) {
				completionCounter++;
				if (completionCounter >= 3) {
					[waiting reportCompletion:nil];
				}
			}
		};
		id childTask;
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		XCTAssertFalse([groupTask restart]);
		
		[_queue addOperationWithBlock:^{
			[groupTask complete:@(99) error:nil];
		}];
	}];
	
	XCTAssertEqual(3, completionCounter);
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	
	id<PowerAuthOperationTask> childAfterComplete = [groupTask createChildTask:^(NSNumber * _Nullable result, NSError * _Nullable error) {
		XCTFail();
	}];
	XCTAssertNil(childAfterComplete);
	
	XCTAssertTrue([groupTask restart]);
	completionCounter = 0;
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTAssertNil(result);
			XCTAssertEqualObjects(@"TestError", error.domain);
			XCTAssertEqual(77, error.code);
			@synchronized (syncToken) {
				completionCounter++;
				if (completionCounter >= 3) {
					[waiting reportCompletion:nil];
				}
			}
		};
		id childTask;
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		childTask = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask);
		XCTAssertFalse([groupTask restart]);
		
		[_queue addOperationWithBlock:^{
			NSError * failure = [NSError errorWithDomain:@"TestError" code:77 userInfo:nil];
			[groupTask complete:nil error:failure];
		}];
	}];
	
	XCTAssertEqual(3, completionCounter);
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	XCTAssertEqual(0, groupTask.testOperation.monitorCancelCount);
	
	childAfterComplete = [groupTask createChildTask:^(NSNumber * _Nullable result, NSError * _Nullable error) {
		XCTFail();
	}];
	XCTAssertNil(childAfterComplete);
	XCTAssertEqual(1, groupTask.monitorOnTaskRestartCount);
}

- (void) testChildCancel
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	NSNumber * syncToken = [[NSNumber alloc] init];
	__block NSInteger completionCounter = 0;
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTAssertEqual(99, [result integerValue]);
			XCTAssertNil(error);
			@synchronized (syncToken) {
				completionCounter++;
				if (completionCounter >= 2) {
					[waiting reportCompletion:nil];
				}
			}
		};
		id<PowerAuthOperationTask> childTask1, childTask2, childTask3;
		childTask1 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask1);
		childTask2 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask2);
		childTask3 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask3);
		XCTAssertFalse([groupTask restart]);
		
		[childTask2 cancel];
		
		[_queue addOperationWithBlock:^{
			[groupTask complete:@(99) error:nil];
		}];
	}];
	
	XCTAssertEqual(2, completionCounter);
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	XCTAssertEqual(0, groupTask.testOperation.monitorCancelCount);
	
	id<PowerAuthOperationTask> childAfterComplete = [groupTask createChildTask:^(NSNumber * _Nullable result, NSError * _Nullable error) {
		XCTFail();
	}];
	XCTAssertNil(childAfterComplete);
}

- (void) testChildCancelAll
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Automatically complete helper when task is complete.
		groupTask.waiting = waiting;
		
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTFail();
		};
		id<PowerAuthOperationTask> childTask1, childTask2, childTask3;
		childTask1 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask1);
		childTask2 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask2);
		childTask3 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask3);
		XCTAssertFalse([groupTask restart]);
		
		[childTask2 cancel];
		[childTask1 cancel];
		[childTask3 cancel];
	}];
	
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	XCTAssertEqual(1, groupTask.testOperation.monitorCancelCount);
	
	id<PowerAuthOperationTask> childAfterComplete = [groupTask createChildTask:^(NSNumber * _Nullable result, NSError * _Nullable error) {
		XCTFail();
	}];
	XCTAssertNil(childAfterComplete);
}

- (void) testChildCancelAllButContinue
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	groupTask.cancelWhenNoChildOperationIsSet = NO;
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Automatically complete helper when task is complete.
		groupTask.waiting = waiting;
		
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTFail();
		};
		id<PowerAuthOperationTask> childTask1, childTask2, childTask3, childTask4;
		childTask1 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask1);
		childTask2 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask2);
		childTask3 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask3);
		XCTAssertFalse([groupTask restart]);
		
		[childTask2 cancel];
		[childTask1 cancel];
		[childTask3 cancel];
		
		childTask4 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask4);
		[childTask4 cancel];
		
		[_queue addOperationWithBlock:^{
			[groupTask complete:@(99) error:nil];
		}];
	}];
	
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	XCTAssertEqual(0, groupTask.testOperation.monitorCancelCount);
}

- (void) testNoOperationAssigned
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	groupTask.onTaskStartBlock = ^(TestGroupTask* groupTask){
		NSLog(@"Starting task but no operation will be assigned...");
	};
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Automatically complete helper when task is complete.
		groupTask.waiting = waiting;
		
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTAssertNil(result);
			XCTAssertEqualObjects(PowerAuthErrorDomain, error.domain);
			XCTAssertEqual(PowerAuthErrorCode_OperationCancelled, error.code);
		};
		id<PowerAuthOperationTask> childTask1, childTask2, childTask3;
		childTask1 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask1);
		childTask2 = [groupTask createChildTask:completionBlock];
		XCTAssertNil(childTask2);
		childTask3 = [groupTask createChildTask:completionBlock];
		XCTAssertNil(childTask3);
	}];
	
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
}

- (void) testReplaceOperation
{
	TestGroupTask * groupTask = [[TestGroupTask alloc] init];
	TestOperationTask * operation1 = [[TestOperationTask alloc] init];
	TestOperationTask * operation2 = [[TestOperationTask alloc] init];
	
	groupTask.onTaskStartBlock = ^(TestGroupTask* groupTask) {
		[groupTask addCancelableOperation:operation1];
	};
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Automatically complete helper when task is complete.
		groupTask.waiting = waiting;
		
		void (^completionBlock)(NSNumber *, NSError *) = ^(NSNumber * result, NSError * error) {
			XCTAssertNil(result);
			XCTAssertEqualObjects(PowerAuthErrorDomain, error.domain);
			XCTAssertEqual(PowerAuthErrorCode_OperationCancelled, error.code);
		};
		id<PowerAuthOperationTask> childTask1, childTask2, childTask3;
		childTask1 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask1);
		childTask2 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask2);
		childTask3 = [groupTask createChildTask:completionBlock];
		XCTAssertNotNil(childTask3);
		
		[_queue addOperationWithBlock:^{
			[groupTask replaceCancelableOperation:operation2];
			[_queue addOperationWithBlock:^{
				[groupTask cancel];
			}];
		}];
	}];
	
	XCTAssertEqual(1, groupTask.monitorOnTaskStartCount);
	XCTAssertEqual(1, groupTask.monitorOnTaskCompleteCount);
	XCTAssertEqual(0, operation1.monitorCancelCount);
	XCTAssertEqual(1, operation2.monitorCancelCount);
}

@end
