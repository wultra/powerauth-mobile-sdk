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

#import <XCTest/XCTest.h>
#import <PowerAuth2/PowerAuth2.h>
#import "AsyncHelper.h"

#import "PA2AsyncOperation.h"

@interface PA2AsyncOperationTests : XCTestCase
@end

@implementation PA2AsyncOperationTests
{
	NSOperationQueue * _serialQueue;
	NSOperationQueue * _concurrentQueue;
}

#pragma mark - Helpers

- (void) setUp
{
	[super setUp];
	_serialQueue = [[NSOperationQueue alloc] init];
	_serialQueue.maxConcurrentOperationCount = 1;
	_serialQueue.name = [[self.class description] stringByAppendingString:@"_Serial"];
	_concurrentQueue = [[NSOperationQueue alloc] init];
	_concurrentQueue.name = [[self.class description] stringByAppendingString:@"_Concurrent"];
}

- (void) tearDown
{
	[super tearDown];
	[_serialQueue cancelAllOperations];
	[_concurrentQueue cancelAllOperations];
	[AsyncHelper waitForQueuesCompletion:@[_serialQueue, _concurrentQueue]];
}

#define RUN_COUNT 13

#define DEF_ATOMIC(counter) AtomicCounter * counter = [[AtomicCounter alloc] init];

#define INC_ATOMIC(counter) [counter increment];

#define INC_COMPLETE(counter, waiting, result)			\
	[counter incrementUpTo:RUN_COUNT completion:^{		\
		[waiting reportCompletion:result];				\
	}];

static void dispatch_later(NSTimeInterval after, void (^block)(void))
{
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(after * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), block);
}

#pragma mark - Tests

- (void) testAsyncOperationSuccessExecution
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	NSString * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				[op completeWithResult:@"success" error:nil];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_ATOMIC(canceled);
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_COMPLETE(reported, waiting, op.operationResult);
			};
			[_serialQueue addOperation:operation];
		}
	}];
	XCTAssertEqual(RUN_COUNT, executed.value);
	XCTAssertEqual(0, canceled.value);
	XCTAssertEqual(RUN_COUNT, reported.value);
	XCTAssertEqual(@"success", result);
}

- (void) testAsyncOperationFailureExecution
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				NSError * error = [[NSError alloc] initWithDomain:@"TestDomain" code:99 userInfo:nil];
				[op completeWithResult:nil error:error];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_ATOMIC(canceled);
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_COMPLETE(reported, waiting, op.operationError);
			};
			[_serialQueue addOperation:operation];
		}
	}];
	XCTAssertEqual(RUN_COUNT, executed.value);
	XCTAssertEqual(0, canceled.value);
	XCTAssertEqual(RUN_COUNT, reported.value);
	XCTAssertTrue([result isKindOfClass:[NSError class]]);
	XCTAssertEqual(@"TestDomain", [(NSError*)result domain]);
	XCTAssertEqual(99, [(NSError*)result code]);
}

- (void) testAsyncOperationCancel
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_COMPLETE(canceled, waiting, @"cancel");
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_ATOMIC(reported);
			};
			[_concurrentQueue addOperation:operation];
			dispatch_later(0.1, ^{ [operation cancel]; });
		}
	} wait:2.0];
	XCTAssertEqual(RUN_COUNT, executed.value);
	XCTAssertEqual(RUN_COUNT, canceled.value);
	XCTAssertEqual(0, reported.value);
	XCTAssertEqual(@"cancel", result);
}

- (void) testAsyncOperationCancelFromExecution
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				[op cancel];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_COMPLETE(canceled, waiting, @"cancel-handler");
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_ATOMIC(reported);
			};
			[_serialQueue addOperation:operation];
		}
	} wait:2.0];
	XCTAssertEqual(RUN_COUNT, executed.value);
	XCTAssertEqual(RUN_COUNT, canceled.value);
	XCTAssertEqual(0, reported.value);
	XCTAssertEqual(@"cancel-handler", result);
}

- (void) testAsyncOperationCancelAfterEnqueue
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_COMPLETE(canceled, waiting, @"cancel-handler");
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_ATOMIC(reported);
			};
			[_serialQueue addOperation:operation];
			[operation cancel];
		}
	} wait:2.0];
	// executed counter cannot be evaluated here
	XCTAssertEqual(RUN_COUNT, canceled.value);
	XCTAssertEqual(0, reported.value);
	XCTAssertEqual(@"cancel-handler", result);
}

- (void) testAsyncOperationCancelAfterEnqueueButNotExecuted
{
	DEF_ATOMIC(executed);
	DEF_ATOMIC(canceled);
	DEF_ATOMIC(reported);
	id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		for (int i = 0; i < RUN_COUNT; i++) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				INC_ATOMIC(executed);
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				INC_COMPLETE(canceled, waiting, @"cancel-handler");
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				INC_ATOMIC(reported);
			};
			[_serialQueue addOperationWithBlock:^{
				[NSThread sleepForTimeInterval:0.3];
			}];
			[_serialQueue addOperation:operation];
			[operation cancel];
		}
	} wait:2.0];
	XCTAssertEqual(0, executed.value);
	XCTAssertEqual(RUN_COUNT, canceled.value);
	XCTAssertEqual(0, reported.value);
	XCTAssertEqual(@"cancel-handler", result);
}

@end
