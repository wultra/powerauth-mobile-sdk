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

#import <Foundation/Foundation.h>

/**
 AsyncHelper allows you to linearize execution of any asynchronous operation.
 The typical usage pattern for this class looks like this:
 
	 id result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper * waiting) {
		// Start any asynchronous operation in the block
		Operation * op = [YourClass yourAsyncOperation:^(BOOL success) {
			// This is a completion block for your async operation
			[waiting reportCompletion:@"SUCCESS"];
		}];
		[op start];
	 }];
	 NSLog(@"Operation ended with %@", result);		// Will print: "Operation ended with: SUCCESS"

 WARNING: Do not use this class in the production application. The internal implementation is
          sufficient for the testing purposes, but it's still kind of multithread anti-pattern.
 */
@interface AsyncHelper : NSObject

/**
 Creates a new instance of AsyncHelper and immediately executes the provided block.
 In the block, you can start any asynchronous operation with any completion, but once
 you exit the |block|, the execution ends in a waiting loop. You have to call 
 [waiting reportCompletion:object] to break the waiting loop. If you don't report 
 the completion in predefined time (10 seconds), then the exception is thrown.
 
 The method returns the same |resultObject| as you previously passed to `-reportCompletion:`.
 */
+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block;

/**
 Creates a new instance of AsyncHelper and immediately executes the provided |block|.
 In the block, you can start any asynchronous operation with any completion, but once
 you exit the |block|, the execution ends in a waiting loop. Then, you have to call
 `[waiting reportCompletion:object]` to break the waiting loop. If you don't report
 the completion in reqested |interval| time, then the exception is thrown.
 
 The method returns the same |resultObject| as you previously passed to `-reportCompletion:`.
 */
+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block
							   wait:(NSTimeInterval)interval;

/**
 Reports completion to a waiting object and breaks the waiting loop. The result can be reported
 from an arbitrary thread.
 */
- (void) reportCompletion:(id)resultObject;


@end
