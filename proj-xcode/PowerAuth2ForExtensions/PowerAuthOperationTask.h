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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 Protocol representing an asynchronous operation created in PowerAuth SDK.
 */
@protocol PowerAuthOperationTask <NSObject>

/**
 Flag indicating if the task was cancelled.
 */
@property (nonatomic, assign, readonly) BOOL isCancelled;

/**
 Cancels the task.
 */
- (void) cancel;

@end

// Make NSOperation compatible with PowerAuthOperationTask (it already is, we need
// to just make compiler happy with the object types)
@interface NSOperation (PowerAuthTaskCompatibility) <PowerAuthOperationTask>
@end
