/**
 * Copyright 2017 Wultra s.r.o.
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

#import "AsyncHelper.h"

@implementation AsyncHelper
{
	dispatch_semaphore_t _semaphore;
	id _result;
}

- (id) init
{
	self = [super init];
	if (self) {
		_semaphore = dispatch_semaphore_create(0);
		if (_semaphore == NULL) {
			return nil;
		}
	}
	return self;
}

+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block
							   wait:(NSTimeInterval)interval
{
	if (!block) {
		return nil;
	}
	AsyncHelper * waiting = [[AsyncHelper alloc] init];
	if (!waiting) {
		@throw [NSException exceptionWithName:@"SoapApi" reason:@"Can't create synchronization semaphore" userInfo:nil];
		return nil;
	}
	block(waiting);
	return [waiting waitForCompletion:interval];
}

+ (id) synchronizeAsynchronousBlock:(void(^)(AsyncHelper * waiting))block
{
	return [self synchronizeAsynchronousBlock:block wait:10.0];
}

- (void) reportCompletion:(id)resultObject
{
	_result = resultObject;
	dispatch_semaphore_signal(_semaphore);
}

- (id) waitForCompletion:(NSTimeInterval)waitingTime
{
	NSUInteger attempts = (NSUInteger)(waitingTime * 2);		// wt / (0.25 + 0.25) => wt * 2 => attempts
	long triggered = 0;
	while (attempts > 0) {
		// We need to prevent possible deadlocks, between our semaphore and the mesagess, processed in the runloop.
		// So, at first, we will try to process current runloop for a while and then, our semaphore will wait.
		[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
		triggered = dispatch_semaphore_wait(_semaphore, dispatch_time(DISPATCH_TIME_NOW, 0.25*NSEC_PER_SEC));
		if (triggered == 0) {
			break;
		}
	}
	if (triggered != 0) {
		@throw [NSException exceptionWithName:@"SoapApi" reason:@"waitForCompletion timed out" userInfo:nil];
	}
	return _result;
}

@end
