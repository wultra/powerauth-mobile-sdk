/*
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
#import "PA2WeakArray.h"
#import "PA2AsyncOperation.h"
#import "AsyncHelper.h"

@interface PA2WeakArrayTests : XCTestCase
@end

@interface PA2WeakArray (Test)
- (BOOL) hasString:(NSString*)str;
@end

@implementation PA2WeakArrayTests
{
	NSOperationQueue * _queue;
}

- (void)setUp
{
	_queue = [[NSOperationQueue alloc] init];
	_queue.maxConcurrentOperationCount = 4;
	_queue.name = [self.class description];
}

- (void)tearDown
{
	[_queue cancelAllOperations];
	[AsyncHelper waitForQueuesCompletion:@[_queue]];
}

- (void) testWeakArrayCleanup
{
	PA2WeakArray<NSString*> * array = [[PA2WeakArray alloc] initWithCapacity:8];
	
	@autoreleasepool
	{
		NSString * T1 = [self getTestString];
		NSString * T2 = [self getTestString];
		NSString * T3 = [self getTestString];
		
		[self captureString:T1 toWeakArray:array forAWhile:0.5];
		[self captureString:T2 toWeakArray:array forAWhile:0.3];
		[self captureString:T3 toWeakArray:array forAWhile:0.8];

		XCTAssertTrue([array hasString:T1]);
		XCTAssertTrue([array hasString:T2]);
		XCTAssertTrue([array hasString:T3]);
		
		NSLog(@"All captured, waiting...");
	}
	
	[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:2.5]];
	NSUInteger remainingCount = [array allNonnullObjects].count;
	XCTAssertEqual(0, remainingCount);
	
	NSLog(@"Done. Remaining count is %@", @(remainingCount));
}

- (NSString*) getTestString
{
	UInt8 bytes[33];
	arc4random_buf(bytes, sizeof(bytes));
	NSData * data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
	return [data base64EncodedStringWithOptions:0];
}

- (void) captureString:(NSString*)string toWeakArray:(PA2WeakArray*)array forAWhile:(NSTimeInterval)time
{
	[array addWeakObject:[self captureString:string forAWhile:time]];
}

- (NSString*) captureString:(NSString*)string forAWhile:(NSTimeInterval)time
{
	NSString * victim = [NSString stringWithFormat:@"%@", string];
	[_queue addOperationWithBlock:^{
		NSLog(@"Keeping string '%@' for %f seconds...", victim, time);
		[NSThread sleepForTimeInterval:time];
		NSLog(@"Releasing string: %@", victim);
	}];
	return victim;
}

@end

@implementation PA2WeakArray (Test)

- (BOOL) hasString:(NSString *)str
{
	return [self findObjectUsingBlock:^BOOL(id  _Nonnull item) {
		return [(NSString*)item isEqualToString:str];
	}] != nil;
}

@end
