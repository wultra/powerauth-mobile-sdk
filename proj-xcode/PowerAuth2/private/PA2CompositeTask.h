/*
 * Copyright 2023 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthOperationTask.h>

/// The `PA2CompositeTask` allows you to execute multiple operation tasks as an one
/// cancelable operation exposed to the application.
@interface PA2CompositeTask : NSObject<PowerAuthOperationTask>

/// Initialize object with optional cancel block.
/// - Parameter cancelBlock: Optional cancel block called when operation is canceled.
- (instancetype) initWithCancelBlock:(void(^)(void))cancelBlock;

/// Replace underlying operation task with new task. If this composite task is already canceled, then
/// the provided task is also canceled.
/// - Parameter operationTask: New underlying task.
/// - Returns: YES if composite operation is not canceled yet and task was replaced, otherwise NO.
- (BOOL) replaceOperationTask:(id<PowerAuthOperationTask>)operationTask;

/// Set operation as completed.
/// - Returns: YES if composite operation is not canceled or completed yet.
- (BOOL) setCompleted;

@end
