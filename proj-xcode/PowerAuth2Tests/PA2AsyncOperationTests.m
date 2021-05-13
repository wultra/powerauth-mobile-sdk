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
	NSOperationQueue * _queue;
}

#pragma mark - Helpers

- (NSOperationQueue*) serialQueue
{
	if (!_queue) {
		_queue = [[NSOperationQueue alloc] init];
		_queue.maxConcurrentOperationCount = 1;
		_queue.name = @"PA2AsyncOperationTests_Serial";
	}
	return _queue;
}


- (void) completeOperationWithCancel:(PA2AsyncOperation*)op
							 waiting:(AsyncHelper*)waiting
						  afterDelay:(NSTimeInterval)delay
{
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		[op cancel];
		[waiting reportCompletion:@"cancel"];
	});
}

- (void) completeOperationWithResult:(NSString*)result
						   operation:(PA2AsyncOperation*)op
							 waiting:(AsyncHelper*)waiting
						  afterDelay:(NSTimeInterval)delay
{
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		[op completeWithResult:result error:nil];
		[waiting reportCompletion:result];
	});
}

- (void) completeOperationWithError:(NSError*)error
						  operation:(PA2AsyncOperation*)op
							waiting:(AsyncHelper*)waiting
						 afterDelay:(NSTimeInterval)delay
{
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		[op completeWithResult:nil error:error];
		[waiting reportCompletion:error];
	});
}

#pragma mark - Tests

- (void) testAsyncOperationSuccessExecution
{
	for (int i = 0; i < 3; i++) {
		__block BOOL executed = NO;
		__block BOOL canceled = NO;
		__block NSInteger reported = 0;
		NSString * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				executed = YES;
				[self completeOperationWithResult:@"success" operation:op waiting:waiting afterDelay:0.1];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				canceled = YES;
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				reported++;
			};
			[[self serialQueue] addOperation:operation];
		}];
		XCTAssertEqual(YES, executed);
		XCTAssertEqual(NO, canceled);
		XCTAssertEqual(1, reported);
		XCTAssertEqual(@"success", result);
	}
}

- (void) testAsyncOperationFailureExecution
{
	for (int i = 0; i < 3; i++) {
		__block BOOL executed = NO;
		__block BOOL canceled = NO;
		__block NSInteger reported = 0;
		id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				executed = YES;
				NSError * error = [[NSError alloc] initWithDomain:@"TestDomain" code:99 userInfo:nil];
				[self completeOperationWithError:error operation:op waiting:waiting afterDelay:0.1];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				canceled = YES;
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				reported++;
			};
			[[self serialQueue] addOperation:operation];
		} wait:2.0];
		XCTAssertEqual(YES, executed);
		XCTAssertEqual(NO, canceled);
		XCTAssertEqual(1, reported);
		XCTAssertTrue([result isKindOfClass:[NSError class]]);
		XCTAssertEqual(@"TestDomain", [(NSError*)result domain]);
		XCTAssertEqual(99, [(NSError*)result code]);
	}
}

- (void) testAsyncOperationCancel
{
	for (int i = 0; i < 3; i++) {
		__block BOOL executed = NO;
		__block BOOL canceled = NO;
		__block NSInteger reported = 0;
		id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				executed = YES;
				[self completeOperationWithCancel:op waiting:waiting afterDelay:0.1];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				canceled = YES;
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				reported++;
			};
			[[self serialQueue] addOperation:operation];
		} wait:2.0];
		XCTAssertEqual(executed, YES);
		XCTAssertEqual(canceled, YES);
		XCTAssertEqual(0, reported);
		XCTAssertEqual(@"cancel", result);
	}
}

- (void) testAsyncOperationImmediateCancel
{
	for (int i = 0; i < 3; i++) {
		__block BOOL executed = NO;
		__block BOOL canceled = NO;
		__block NSInteger reported = 0;
		id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
			PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
			operation.executionBlock = ^id(PA2AsyncOperation *op) {
				executed = YES;
				[op cancel];
				[self completeOperationWithResult:@"success" operation:op waiting:waiting afterDelay:0.3];
				return nil;
			};
			operation.cancelBlock = ^(PA2AsyncOperation *op, id operationTask) {
				[waiting reportCompletion:@"cancel-handler"];
				canceled = YES;
			};
			operation.reportBlock = ^(PA2AsyncOperation *op) {
				reported++;
			};
			[[self serialQueue] addOperation:operation];
		} wait:2.0];
		XCTAssertEqual(executed, YES);
		XCTAssertEqual(canceled, YES);
		XCTAssertEqual(0, reported);
		XCTAssertEqual(@"cancel-handler", result);
	}
}

@end
