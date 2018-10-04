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

#import "PA2HttpRequest.h"
#import "PA2RestResponseStatus.h"
#import "PA2OperationTask.h"

/**
 The `PA2AsyncOperation` implements a simple asynchronous NSOperation,
 which delegates its operation to "executionBlock". You can also specify
 "cancelBlock", to handle custom object cancelations and "reportBlock",
 which is issued to the "reportQueue".
 */
@interface PA2AsyncOperation: NSOperation

#pragma mark - Initialization & setup

/**
 Initializes object with dispatch queue, designated for completion reporting.
 */
- (id) initWithReportQueue:(dispatch_queue_t)queue;

/**
 Block called from operation's main. The object returned from the block is
 then assigned to the "operationTask".
 */
@property (nonatomic, strong) id (^executionBlock)(PA2AsyncOperation * op);

/**
 Block called when the operation is cancelled.
 */
@property (nonatomic, strong) void (^cancelBlock)(PA2AsyncOperation * op, id operationTask);

/**
 Block which is safely issued to the "report" queue, after the operation is finished.
 The report block is not called when operation was cancelled.
 */
@property (nonatomic, strong) void (^reportBlock)(PA2AsyncOperation * op);

#pragma mark - Runtime data

/**
 Property available for an operation implementation. You can use this to keep
 underlying operation task object, like NSURLDataTask. The execution block must
 return such object, which is then assigned to this property.
 */
@property (nonatomic, strong, readonly) id operationTask;

#pragma mark - Completion

/**
 The result of the operation. Value is updated from "completeWithResult" method.
 */
@property (nonatomic, strong, readonly) id operationResult;

/**
 COntains an error object passed to "completeWithResult" method.
 */
@property (nonatomic, strong, readonly) NSError * operationError;

/**
 Completes operation with result or with error, or with both.
 */
- (void) completeWithResult:(id)result error:(NSError*)error;

@end

// Make NSOperation compatible with PA2OperationTask (it already is, we need
// to just make compiler happy with the object types)
@interface NSOperation (TaskCompatibility) <PA2OperationTask>
@end
