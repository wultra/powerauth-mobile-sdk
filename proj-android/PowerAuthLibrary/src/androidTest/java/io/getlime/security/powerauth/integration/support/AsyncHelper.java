/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support;

import android.os.Debug;

import androidx.annotation.NonNull;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The {@code AsyncHelper} class helps synchronize asynchronous tasks. Simply call {@link #await(Execution)}
 * or {@link #awaitNoThrow(Execution)} methods to execute {@link Execution} closure immediately. The
 * execution closure gets {@link ResultCatcher} object in its input parameter. You must use that object to
 */
public class AsyncHelper {

    /**
     * Class that catch result from asynchronous operation.
     * @param <TResult> Type of result object.
     */
    public static class ResultCatcher<TResult> {

        private final @NonNull CountDownLatch signal;
        private TResult result;
        private Throwable throwable;
        private boolean completed;

        /**
         * Construct result catcher with synchronization primitive.
         * @param signal Signal that must be notified about completion.
         */
        private ResultCatcher(final @NonNull CountDownLatch signal) {
            this.signal = signal;
        }

        /**
         * Complete synchronized operation with success but with no result.
         */
        public synchronized void completeWithSuccess() {
            setCompleted(null, null);
        }

        /**
         * Complete synchronized operation with success and with result object.
         * @param result Result object to be returned back to the test.
         */
        public synchronized void completeWithResult(TResult result) {
            setCompleted(result, null);
        }

        /**
         * Complete synchronized operation with failure.
         * @param error Error to report back to the test.
         */
        public synchronized void completeWithError(Throwable error) {
            setCompleted(null, error);
        }

        /**
         * @return Return result reported from asynchronous operation.
         */
        public synchronized TResult getResult() {
            if (!completed) {
                throw new IllegalStateException("Result catcher has no result yet.");
            }
            return result;
        }

        /**
         * @return Error reported from asynchronous operation.
         */
        public synchronized Throwable getThrowable() {
            if (!completed) {
                throw new IllegalStateException("Result catcher has no result yet.");
            }
            return throwable;
        }

        /**
         * Set asynchronous operation as completed.
         */
        private void setCompleted(TResult result, Throwable error) {
            if (completed) {
                throw new IllegalStateException("Result catcher already has result.");
            }
            this.result = result;
            this.throwable = error;
            this.completed = true;
            signal.countDown();
        }
    }

    /**
     * Interface that allows start of asynchronous operation.
     * @param <TResult> Type of result object.
     */
    public interface Execution<TResult> {
        /**
         * Start your asynchronous operation. Your implementation get a {@link ResultCatcher} object
         * that allows you report result of the operation once it completes its execution.
         *
         * @param resultCatcher A result catcher that allows you report the result of the asynchronous operation.
         * @throws Exception In case of failure.
         */
        void execute(@NonNull ResultCatcher<TResult> resultCatcher) throws Exception;
    }

    /**
     * Synchronize asynchronous operation. This variant of synchronization wraps and re-throws an exception
     * reported from the asynchronous operation.
     *
     * @param executionBlock Execution block that must implement start of asynchronous operation.
     * @param <TResult> Type of result.
     * @return Result reported from asynchronous operation.
     * @throws Exception In case of failure, or operation doesn't finish in defined waiting time.
     */
    public static <TResult> TResult await(@NonNull Execution<TResult> executionBlock) throws Exception {
        return synchronizeImpl(true, executionBlock);
    }

    /**
     * Synchronize asynchronous operation. This variant of synchronization ignore errors reported
     * from asynchronous operation.
     *
     * @param executionBlock Execution block that must implement start of asynchronous operation.
     * @param <TResult> Type of result.
     * @return Result reported from asynchronous operation or null in case of error.
     * @throws Exception Operation doesn't finish in defined waiting time.
     */
    public static <TResult> TResult awaitNoThrow(@NonNull Execution<TResult> executionBlock) throws Exception {
        return synchronizeImpl(false, executionBlock);
    }

    /**
     * Internal implementation of synchronization.
     *
     * @param throwOnError If false, error reported from asynchronous operation will be ignored.
     * @param executionBlock Execution block that must implement start of asynchronous operation.
     * @param <TResult> Type of result.
     * @return Result reported from asynchronous operation or null in case of ignored error.
     * @throws Exception In case of not-ignored failure, or operation doesn't finish in defined waiting time.
     */
    private static <TResult> TResult synchronizeImpl(boolean throwOnError, @NonNull Execution<TResult> executionBlock) throws Exception {
        final CountDownLatch signal = new CountDownLatch(1);
        final ResultCatcher<TResult> resultCatcher = new ResultCatcher<>(signal);
        executionBlock.execute(resultCatcher);
        final long awaitTimeout = Debug.isDebuggerConnected() ? 100 : 10; // give more time to developer to debug the things
        boolean completed = signal.await(awaitTimeout, TimeUnit.SECONDS);
        if (!completed) {
            throw new Exception("Asynchronous operation did not finish in time.");
        }
        Throwable throwable = resultCatcher.getThrowable();
        if (throwable != null) {
            if (throwOnError) {
                throw new Exception("Asynchronous operation failed with exception: " + throwable.getMessage(), throwable);
            } else {
                Logger.e("Asynchronous operation failed with exception: " + throwable.getMessage());
            }
        }
        return resultCatcher.getResult();
    }
}
