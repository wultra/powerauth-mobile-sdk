/*
 * Copyright 2022 Wultra s.r.o.
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthOperationTask.h>

#pragma mark - Grouped task

@class PA2ChildTask<ResultType>;

/**
 The PA2GroupedTask implements task grouping. The class is useful in cases
 when needs to group multiple application's requests for the same resource
 in one actual HTTP request.
 
 You suppose to subclass this object and override at least `onTaskStart` method.
 */
@interface PA2GroupedTask<ResultType>: NSObject<PowerAuthOperationTask>

#pragma mark - Public methods
/**
 Initialize object with no shared lock. The locking object is created internally.
 */
- (nonnull instancetype) init;

/**
 Initialize object with a shared lock that will be used as a thread synchronization primitive.
 Be aware that the lock must support recursive locking.
 */
- (nonnull instancetype) initWithSharedLock:(nonnull id<NSLocking>)sharedLock
                                   taskName:(nullable NSString*)taskName;

/**
 Restarts the task. Returns YES if task has been restarted and you can add more child tasks.
 If NO is returned, then the task is still in progress.
 */
- (BOOL) restart;

/**
 Complete this grouped operation with result or failure.
 */
- (void) complete:(nullable ResultType)result error:(nullable NSError*)error;

/**
 Create child task that will be associated with this grouped task. The child task should to be returned
 back to the application as `PowerAuthOperationTask` implementation.
 */
- (nullable PA2ChildTask<ResultType>*) createChildTask:(void(^_Nonnull)(ResultType _Nullable result, NSError * _Nullable error))completion;

/**
 Remove previously created child task. This method is typically called from the child task itself from cancel method.
 */
- (void) removeChildTask:(nonnull id<PowerAuthOperationTask>)operation;

/**
 Associate internal cancelable operation to the group task. The function return YES if operation has been added and NO
 if this group task is already finished.
 */
- (BOOL) addCancelableOperation:(nonnull id<PowerAuthOperationTask>)cancelable;

/**
 Replace the current cancelable operation with a new one. The current cancelable operation is removed from the internal list
 only if the list contains single operation. The function return YES if operation has been added and NO if this group
 task is already finished.
 */
- (BOOL) replaceCancelableOperation:(nonnull id<PowerAuthOperationTask>)cancelable;

#pragma mark - Methods to override

/**
 Called when the first child task is created. The subclass implementation must call super and add at least one cancelable operation.
 */
- (void) onTaskStart;

/**
 Called from restart method, when task is being restarted. The subclass implementation must call super and add at least one cancelable operation.
 */
- (void) onTaskRestart;

/**
 Called when the group task is completed with the result or error or is automatically cancelled. If task is automatically canceled,
 then both parameters are nil. The subclass implementation must call super.
 */
- (void) onTaskCompleteWithResult:(nullable ResultType)result error:(nullable NSError*)error;

/**
 The default implementation return `YES`, so when there's no child task associated to this group, then the whole task is canceled.
 The subclass implementation may override this behavior in case that it's important to complete the operation even if the application
 no longer wants the result. For example, if the protocol upgrade is performed, then it's important to complete the upgrade.
 */
- (BOOL) shouldCancelWhenNoChildOperationIsSet;

#pragma mark - Thread synchronization

/**
 The property contains lock used internally.
 */
@property (nonatomic, strong, readonly, nonnull) id<NSLocking> lock;

/**
 Execute block when internal lock is acquired.
 */
- (void) synchronizedVoid:(void(NS_NOESCAPE ^ _Nonnull)(void))block;

/**
 Execute block when internal lock is acquired and return result created in the block.
 */
- (nullable id) synchronized:(id _Nullable (NS_NOESCAPE ^ _Nonnull)(void))block;

@end


#pragma mark - Child task

/**
 The PA2ChildTask associate one particula application's request with completion with a group task.
 */
@interface PA2ChildTask<ResultType>: NSObject<PowerAuthOperationTask>

/**
 Initialize the object with parent task and with the completion closure. The reference to parent task is weak.
 */
- (nonnull instancetype) initWithParentTask:(nonnull PA2GroupedTask<ResultType>*)parentTask
                                 completion:(void(^_Nonnull)(ResultType _Nullable result, NSError * _Nullable error))completion;
/**
 Complete this task with result or error.
 */
- (void) complete:(nullable ResultType)result error:(nullable NSError*)error;

@end
