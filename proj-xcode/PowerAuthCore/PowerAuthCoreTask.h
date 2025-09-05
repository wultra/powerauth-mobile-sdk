/*
 * Copyright 2025 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCoreRequest.h>

@interface PowerAuthCoreTask : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains name of the task. The value can be used only for the debugging purposes.
@property (nonatomic, readonly, strong, nonnull) NSString * taskName;

/// Contains YES if the request is finished no matter of the result. Use `isCompleted`,
/// `isCanceled` or `isFailed` to determine the exact result.
@property (nonatomic, readonly) BOOL isDone;

/// Contains `YES` if task is completed with success
@property (nonatomic, readonly) BOOL isCompleted;

/// Contains `YES` if task is completed with failure.
@property (nonatomic, readonly) BOOL isFailed;

/// Contains `YES` if task is canceled.
@property (nonatomic, readonly) BOOL isCanceled;

/// Contains reason of task failure.
@property (nonatomic, readonly, strong, nullable) NSError* failure;

/// Contains response object if response object was produced in the task.
@property (nonatomic, readonly, strong, nullable) id responseObject;

/// Contains response in JSON representation.
@property (nonatomic, readonly, strong, nullable) id responseJson;

/// Cancel the task.
- (void) cancel;

/// Return next request if task has more requests to execute. If
/// - Parameter error:
/// - Returns: Next request or `nil` if there's no request scheduled or operation failed. Check
///            error pointer to distinguish between this states.
- (nullable PowerAuthCoreRequest*) nextRequest:(NSError*_Nullable*_Nullable)error;

@end
