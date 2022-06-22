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

package io.getlime.security.powerauth.sdk.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The {@code GroupedTask} implements task grouping. The class is useful in cases when needs to group
 * multiple application's requests for the same resource in one actual HTTP request.
 *
 * @param <TResult> Type of result object.
 */
public class GroupedTask<TResult> implements ICancelable {

    public final @NonNull ReentrantLock lock;
    public final @NonNull String taskName;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private final @NonNull List<ChildTask> childTasks;
    private final @NonNull List<ICancelable> operations;

    private TResult successResult;
    private Throwable failureResult;

    private boolean isStarted = false;
    private boolean isFinished = false;
    private boolean isCanceled = false;

    /**
     * Initialize object with all required parameters.
     *
     * @param taskName Name of the task. The name will be visible in the debug log.
     * @param sharedLock Instance of shared lock.
     * @param dispatcher Result dispatcher.
     */
    public GroupedTask(@NonNull String taskName, @NonNull ReentrantLock sharedLock, @NonNull ICallbackDispatcher dispatcher) {
        this.lock = sharedLock;
        this.taskName = taskName + ": ";
        this.callbackDispatcher = dispatcher;
        this.childTasks = new ArrayList<>(1);
        this.operations = new ArrayList<>(1);
    }

    /**
     * Restarts the task. You can restart this grouped task only if it's not started or is already
     * finished.
     * @return true if task has been restarted and more child tasks can be added.
     */
    public boolean restart() {
        try {
            lock.lock();
            final boolean restartResult = !isStarted || isFinished;
            if (restartResult) {
                PowerAuthLog.d(taskName + "Task is restarted");
                isStarted = false;
                isFinished = false;
                isCanceled = false;
                childTasks.clear();
                operations.clear();
                successResult = null;
                failureResult = null;
                onGroupedTaskRestart();
            }
            return restartResult;
        } finally {
            lock.unlock();
        }
    }

    // Child tasks

    /**
     * Create child task that will be associated with this grouped task.
     *
     * @param completion Task completion.
     * @return ICancelable instance or null if this grouped task is already finished.
     */
    public @Nullable ICancelable createChildTask(@NonNull ITaskCompletion<TResult> completion) {
        final ICancelable result;
        final Runnable completionTask;
        try {
            lock.lock();
            if (!isFinished) {
                final ChildTask childTask = new ChildTask(completion);
                childTasks.add(childTask);
                if (!isStarted && childTasks.size() == 1 && !onTaskStart()) {
                    // The task implementation failed to add a cancelable operation.
                    final Throwable failure = new PowerAuthErrorException(PowerAuthErrorCodes.OPERATION_CANCELED, "Internal error. No operation is set");
                    completionTask = onTaskComplete(null, failure, OP_SET_CANCELED);
                } else {
                    completionTask = null;
                }
                result = childTask;
            } else {
                PowerAuthLog.d(taskName + "Task is already finished");
                result = null;
                completionTask = null;
            }
        } finally {
            lock.unlock();
        }
        dispatchResult(completionTask);
        return result;
    }

    /**
     * Remove previously created child task.
     *
     * @param childTask Child task to remove.
     */
    private void removeChildTask(@NonNull ChildTask childTask) {
        final Runnable completionTask;
        try {
            lock.lock();
            childTasks.remove(childTask);
            if (childTasks.isEmpty()) {
                completionTask = onAutomaticTaskCancel();
            } else {
                completionTask = null;
            }
        } finally {
            lock.unlock();
        }
        dispatchResult(completionTask);
    }

    // Cancelable operations

    /**
     * Associate internal cancelable operation to the group task. The function return true if
     * operation has been added and false if this group task is already finished.
     *
     * @param cancelable Cancelable operation to add.
     * @return true if operation has been added, otherwise false.
     */
    public boolean addCancelableOperation(@NonNull ICancelable cancelable) {
        try {
            lock.lock();
            final boolean result = !isFinished;
            if (result) {
                operations.add(cancelable);
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Replace the current cancelable operation with a new one. The current cancelable operation is
     * removed from the internal list only if the list contains single operation. The function
     * return true if operation has been added and false if this group task is already finished.
     *
     * @param cancelable Cancelable operation to replace.
     * @return true if operation has been added or replaced, otherwise false.
     */
    public boolean replaceCancelableOperation(@NonNull ICancelable cancelable) {
        try {
            lock.lock();
            final boolean result = !isFinished;
            if (result) {
                if (operations.size() == 1) {
                    operations.remove(0);
                }
                operations.add(cancelable);
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    // Task completion

    /**
     * Complete this task with result object and report this object to all child tasks.
     *
     * @param result Result object to report to child tasks.
     */
    public void complete(final @NonNull TResult result) {
        final Runnable completionTask;
        try {
            lock.lock();
            completionTask = onTaskComplete(result, null, 0);
        } finally {
            lock.unlock();
        }
        dispatchResult(completionTask);
    }

    /**
     * Complete this task with failure and report this to all child tasks.
     *
     * @param failure Failure to report to child tasks.
     */
    public  void complete(final @NonNull Throwable failure) {
        final Runnable completionTask;
        try {
            lock.lock();
            completionTask = onTaskComplete(null, failure, 0);
        } finally {
            lock.unlock();
        }
        dispatchResult(completionTask);
    }

    /**
     * @return Success result, valid only when task finished with success.
     */
    public @Nullable TResult getSuccessResult() {
        try {
            lock.lock();
            return successResult;
        } finally {
            lock.unlock();
        }
    }

    /**
     * @return Failure exception, valid only when task finished with failure.
     */
    public @Nullable Throwable getFailureResult() {
        try {
            lock.lock();
            return failureResult;
        } finally {
            lock.unlock();
        }
    }

    // ICancelable implementation

    @Override
    public void cancel() {
        final Runnable completionTask;
        try {
            lock.lock();
            final Throwable exception = new PowerAuthErrorException(PowerAuthErrorCodes.OPERATION_CANCELED);
            completionTask = onTaskComplete(null, exception, OP_SET_CANCELED);
        } finally {
            lock.unlock();
        }
        dispatchResult(completionTask);
    }

    @Override
    public boolean isCancelled() {
        try {
            lock.lock();
            return isCanceled;
        } finally {
            lock.unlock();
        }
    }

    // Public start / complete

    /**
     * Overridable method, called when task is started.
     */
    public void onGroupedTaskStart() {
    }

    /**
     * Overridable method, called when task is restarted.
     */
    public void onGroupedTaskRestart() {
    }

    /**
     * Overridable method, called when task is finished.
     * @param result Success result.
     * @param failure Failure result.
     */
    public void onGroupedTaskComplete(@Nullable TResult result, @Nullable Throwable failure) {
    }

    /**
     * The default implementation return true, so when there's no child task associated to this group,
     * then the whole task is canceled. The subclass implementation may override this behavior in
     * case that it's important to complete the operation even if the application no longer wants
     * the result. For example, if the protocol upgrade is performed, then it's important to
     * complete the upgrade.
     *
     * @return true when task should automatically cancel if there's no child task available.
     */
    public boolean groupedTaskShouldCancelWhenNoChildOperationIsSet() {
        return true;
    }

    // Private start / complete / cancel

    /**
     * Start the task internally.
     * <p>
     * The method must be called only when the internal lock is acquired.
     */
    private boolean onTaskStart() {
        isStarted = true;
        PowerAuthLog.d(taskName + "Task is starting");
        onGroupedTaskStart();
        if (operations.isEmpty()) {
            PowerAuthLog.e(taskName + "No operation is registered after task start");
            return false;
        }
        return true;
    }

    private static final int OP_SET_CANCELED    = 0x001;
    private static final int OP_AUTO_CANCEL     = 0x002;

    /**
     * Complete the task with result or failure. If both result and failure objects are null, then
     * the {@link IllegalStateException} is reported. Function returns {@link Runnable} implementation
     * that will delegate result or failure back to all child tasks. The returned runnable should
     * be later executed in callback dispatcher.
     * <p>
     * The method must be called only when the internal lock is acquired.
     *
     * @param result Result to report.
     * @param failure Failure to report.
     * @param flags Operation completion flags, use OP_* constants.
     * @return Runnable with appropriate implementation or null if this task is already completed.
     */
    private @Nullable Runnable onTaskComplete(@Nullable final TResult result, @Nullable final Throwable failure, int flags) {
        if (!isFinished) {
            isFinished = true;
            isCanceled = (flags & OP_SET_CANCELED) == OP_SET_CANCELED;
            if (!isCanceled) {
                if ((flags & OP_AUTO_CANCEL) == 0) {
                    if (result == null) {
                        PowerAuthLog.d(taskName + "Task is complete");
                    } else {
                        PowerAuthLog.d(taskName + "Task is complete with error: " + failure);
                    }
                } else {
                    PowerAuthLog.d(taskName + "Task is complete with automatic cancel");
                }
            } else {
                PowerAuthLog.d(taskName + "Task is canceled from elsewhere");
            }
            final List<ChildTask> childTasksToComplete = childTasks.isEmpty() ? null : new ArrayList<>(childTasks);
            final List<ICancelable> operationsToCancel = (flags & (OP_SET_CANCELED | OP_AUTO_CANCEL)) == 0 ? null : new ArrayList<>(operations);
            childTasks.clear();
            operations.clear();

            successResult = result;
            failureResult = failure;

            // Report result to subclasses
            onGroupedTaskComplete(result, failure);

            if (childTasksToComplete != null || operationsToCancel != null) {
                // If there are child tasks to complete, then create a proper runnable with completion.
                return new Runnable() {
                    @Override
                    public void run() {
                        if (childTasksToComplete != null) {
                            for (ChildTask childTask : childTasksToComplete) {
                                if (result != null) {
                                    childTask.complete(result);
                                } else if (failure != null) {
                                    childTask.complete(failure);
                                } else {
                                    throw new IllegalStateException("Internal SDK failure");
                                }
                            }
                        }
                        if (operationsToCancel != null) {
                            for (ICancelable cancelable : operationsToCancel) {
                                cancelable.cancel();
                            }
                        }
                    }
                };
            }
        }
        return null;
    }

    /**
     * Implements automatic cancel of internal operations in case that task is started
     * and there's no longer child tasks associated in it.
     * <p>
     * The method must be called only when the internal lock is acquired.
     * @return Runnable with cleanup job or null if no cleanup job is required.
     */
    private @Nullable Runnable onAutomaticTaskCancel() {
        if (!isFinished && !isCanceled) {
            if (groupedTaskShouldCancelWhenNoChildOperationIsSet()) {
                return onTaskComplete(null, null, OP_AUTO_CANCEL);
            } else {
                PowerAuthLog.d(taskName + "Task is going to complete itself with no child set");
            }
        }
        return null;
    }

    /**
     * Dispatch result in form of {@link Runnable} implementation with using the callback dispatcher.
     * @param runnable Runnable to execute in callback dispatcher.
     */
    private void dispatchResult(@Nullable Runnable runnable) {
        if (runnable != null) {
            callbackDispatcher.dispatchCallback(runnable);
        }
    }

    // ChildTask implementation

    /**
     * The {@code ChildTask} associates one particular application's request with completion
     * with a parent group task.
     */
    private class ChildTask implements ICancelable {

        private final ITaskCompletion<TResult> completion;
        private boolean isCanceled = false;

        /**
         * Initialize object with parent task and completion listener.
         * @param completion Completion to call once the task is finished.
         */
        ChildTask(@NonNull ITaskCompletion<TResult> completion) {
            this.completion = completion;
        }

        /**
         * Complete task with result.
         * @param result Result to report back to the application.
         */
        void complete(@NonNull TResult result) {
            try {
                lock.lock();
                if (!isCanceled) {
                    isCanceled = true;
                    completion.onSuccess(result);
                }
            } finally {
                lock.unlock();
            }
        }

        /**
         * Complete task with failure.
         * @param failure Failure to report back to the application.
         */
        void complete(@NonNull Throwable failure) {
            try {
                lock.lock();
                if (!isCanceled) {
                    isCanceled = true;
                    completion.onFailure(failure);
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void cancel() {
            try {
                lock.lock();
                if (!isCanceled) {
                    isCanceled = true;
                    removeChildTask(this);
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public boolean isCancelled() {
            return false;
        }
    }
}
