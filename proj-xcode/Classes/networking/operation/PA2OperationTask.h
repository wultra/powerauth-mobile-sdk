/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

/** Class representing a PowerAuth 2.0 client operation.
 
 Operations in PowerAuth 2.0 client consist of multiple steps. First, a request must be prepared - this may require asynchronous call on it's own (for example, access to Keychain would block main thread otherwise). Then, a network request must be created and executed on a separate data task. This task encapsulates all operations under single class.
 */
@interface PA2OperationTask : NSObject

/** Associated data task of a HTTP client communicating with the PowerAuth 2.0 Standard RESTful API. May be null in case data task was not started yet.
 */
@property (nonatomic, strong, nullable) NSURLSessionDataTask *dataTask;

/** Flag indicating if the task was cancelled.
 */
@property (nonatomic, assign, readonly) BOOL isCancelled;

/** Cancels the current task, if an underlying data task is running, it is cancelled as well.
 */
- (void) cancel;

@end
