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

package io.getlime.security.powerauth.core;

import androidx.annotation.Nullable;

/**
 * The {@code CoreTask} object represents a task that covers execution of complex operations
 * composed from multiple HTTP requests.
 * @param <TResponse> Type of response object.
 */
public class CoreTask<TResponse> extends NativeObject {
    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     */
    protected CoreTask(long nativeObjectHandle) {
        super(nativeObjectHandle);
        this.responseBuilderHandle = NATIVE_NULL;
    }

    /**
     * Construct object with handle to native task object and handle to native response object
     * builder. This is a designated constructor used from JNI, when C++ object is being wrapped
     * into Java object.
     * @param nativeObjectHandle Handle to native task object.
     * @param responseBuilderHandle Handle to native response object builder.
     */
    protected CoreTask(long nativeObjectHandle, long responseBuilderHandle) {
        super(nativeObjectHandle);
        this.responseBuilderHandle = responseBuilderHandle;
    }

    /**
     * Handle containing handle to native C++ object translating response into Java model object.
     * The handle is released by calling {@link #updateResponse()} method, or in {@link #finalize()}.
     */
    private final long responseBuilderHandle;

    /**
     * Contains information whether response object is already captured in object's properties.
     * Property is modified from JNI.
     */
    boolean responseIsCaptured;

    /**
     * Contains last failure produced in the request object.
     */
    private Throwable failure;

    /**
     * Contains response object if this kind of task provide some response object.
     * Property is modified from JNI.
     */
    private TResponse responseObject;

    /**
     * Contains response in JSON representation.
     * Property is modified from JNI.
     */
    private Object responseJson;

    @Override
    protected void finalize() {
        try {
            // Make sure the task is also canceled if it has not completed yet. If this happens,
            // it means that the Java wrapper was abandoned and being destroyed before completion.
            // This is important for some tasks that modify pending flags on the parent Session.
            // The cancelIfNotDone() also releases `responseBuilderHandle` if still set.
            cancelIfNotDone();
        } catch (Throwable ignore) {
            // Ignore failures during native cancellation to allow superclass finalization.
        } finally {
            super.finalize();
        }
    }

    /**
     * @return Name of the task. The value can be used only for the debugging purposes.
     */
    public native String getTaskName();

    /**
     * @return {@code true} if the request is finished no matter of the result. Use {@link #isCompleted()},
     *         {@link #isCanceled()} or {@link #isFailed()} to determine the exact result.
     */
    public native boolean isDone();

    /**
     * @return {@code true} if task is completed with success
     */
    public native boolean isCompleted();
    /**
     * @return {@code true} if task is completed with failure.
     */
    public native boolean isFailed();
    /**
     * @return {@code true} if task is canceled.
     */
    public native boolean isCanceled();

    /**
     * @return Response object if such object was produced in the task.
     */
    @Nullable
    public TResponse getResponseObject() throws CoreException {
        try {
            updateResponse();
            return responseObject;
        } catch (CoreException e) {
            failure = e;
            throw e;
        }
    }

    /**
     * @return Response in JSON representation, if available.
     */
    @Nullable
    public Object getResponseJson() throws CoreException {
        try {
            updateResponse();
            return responseJson;
        } catch (CoreException e) {
            failure = e;
            throw e;
        }
    }


    /**
     * Updates response object from the received data.
     * @throws CoreException In case of failure.
     */
    private native void updateResponse() throws CoreException;

    /**
     * Cancel the task.
     */
    public native void cancel();

    /**
     * Cancels the task if it has not completed yet.
     */
    private native void cancelIfNotDone();

    /**
     * Get the next request to execute as a part of this task.
     * @return Next request or {@code null} if there's no request scheduled or operation failed.
     *         Check error pointer to distinguish between this states.
     * @throws CoreException In case of failure.
     */
    @Nullable
    public CoreRequest<TResponse> getNextRequest() throws CoreException {
        try {
            return getNextRequestImpl();
        } catch (CoreException e) {
            failure = e;
            throw e;
        }
    }

    /**
     * Native implementation of getting the next request.
     * @return Next request or {@code null} if there's no request scheduled or operation failed.
     *         Check error pointer to distinguish between this states.
     * @throws CoreException In case of failure.
     */
    @Nullable
    private native CoreRequest<TResponse> getNextRequestImpl() throws CoreException;

    /**
     * @return {@code true} if session's state should be serialized after the task finishes.
     */
    public native boolean isSessionStateSerializationNeeded();
}
