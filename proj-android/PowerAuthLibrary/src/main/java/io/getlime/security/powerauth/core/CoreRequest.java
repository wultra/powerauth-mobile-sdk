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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The {@link CoreRequest} object represents a HTTP request created in core module.
 *
 * @param <TResponse> Type of response.
 */
public class CoreRequest<TResponse> extends NativeObject {

    /**
     * Contains last failure produced in the request object.
     */
    private Throwable failure;

    /**
     * Contains response object if this kind of request provide some response object.
     */
    private TResponse responseObject;

    /**
     * Contains response in JSON representation.
     */
    private Object responseJson;

    /**
     * Handle containing handle to native C++ object translating response into Java model object.
     * The handle is released by calling {@link #processResponse(byte[])} method, or in {@link #finalize()}.
     */
    private final long responseBuilderHandle;

    /**
     * Construct object with handle to native request object. This is a designated constructor
     * used from JNI, when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     */
    protected CoreRequest(long nativeObjectHandle) {
        super(nativeObjectHandle);
        this.responseBuilderHandle = NATIVE_NULL;
    }

    /**
     * Construct object with handle to native request object and with handle to a response object
     * builder. This is a designated constructor used from JNI, when C++ object is being wrapped
     * into Java object.
     * @param nativeObjectHandle Handle to native request object.
     * @param responseBuilderHandle Handle to native response builder.
     */
    protected CoreRequest(long nativeObjectHandle, long responseBuilderHandle) {
        super(nativeObjectHandle);
        this.responseBuilderHandle = responseBuilderHandle;
    }

    @Override
    protected void finalize() {
        try {
            // Make sure the request is also canceled if it has not completed yet. If this happens,
            // it means that the Java wrapper was abandoned and destroyed before completion.
            // This is important for some requests that modify state on the parent Session.
            // The cancel() also releases `responseBuilderHandle` if still set.
            cancel();
        } catch (Throwable ignored) {
            // Ignore failures during native cancellation to allow superclass finalization.
        } finally {
            super.finalize();
        }
    }

    /**
     * Destroy
     */
    public void dispose() {
        NativeObject.safeNativeDestroyHandles(new long[]{ nativeObjectHandle, responseBuilderHandle });
    }

    /**
     * @return Information whether this request require time synchronized with the server.
     */
    public native boolean isRequireSynchronizedTime();

    /**
     * @return Information whether this request require serial queue for its execution.
     */
    public native boolean isRequireSerialQueue();

    /**
     * @return Information whether this request is allowed during the protocol upgrade.
     */
    public native boolean isAllowedInUpgrade();

    /**
     * @return Scope of the temporary encryption key required for the request processing.
     *         If {@link CoreEncryptorScope#NONE} is used, then request has no encryption.
     */
    @CoreEncryptorScope
    public native int getEncryptorScope();

    /**
     * @return Information whether this request is authenticated with authentication header.
     */
    public native boolean isAuthenticated();

    /**
     * @return Relative path to endpoint.
     */
    @NonNull
    public native String getRelativePath();

    /**
     * @return HTTP method.
     */
    @NonNull
    public native String getHttpMethod();

    /**
     * Get HTTP request body. Be aware, that you have to call {@link #prepareRequest()} method
     * to prepare the content of the body.
     * @return HTTP request body.
     * @throws CoreException With {@link CoreErrorCode#NOT_ALLOWED} in case the request is not prepared.
     */
    @NonNull
    public native byte[] getRequestBody() throws CoreException;

    /**
     * Get HTTP request headers. Be aware, that you have to call {@link #prepareRequest()} method
     * to prepare the content of the body.
     * @return HTTP request headers.
     * @throws CoreException With {@link CoreErrorCode#NOT_ALLOWED} in case the request is not prepared.
     */
    @NonNull
    public native CoreHttpHeader[] getRequestHeaders() throws CoreException;

    /**
     * @return {@code true} if the request is finished no matter of the result. Use {@link #isCompleted()},
     *         {@link #isCanceled()}  or {@link #isFailed()} to determine the exact result.
     */
    public native boolean isDone();

    /**
     * @return {@code true} if the request is completed and successfully processed.
     */
    public native boolean isCompleted();

    /**
     * @return {@code true} if the request has been canceled.
     */
    public native boolean isCanceled();

    /**
     * @return {@code true} if the request processing failed.
     */
    public native boolean isFailed();

    /**
     * @return Exception with reason of request or response processing failure.
     */
    @Nullable
    public Throwable getFailure() {
        return failure;
    }

    /**
     * @return Response object if this kind of request provide some response object or null
     *         if response is not yet available.
     */
    @Nullable
    public TResponse getResponseObject() {
        if (isCompleted()) {
            return responseObject;
        }
        return null;
    }

    /**
     * @return Response in JSON representation or null if response is not yet available.
     */
    @Nullable
    public Object getResponseJson() {
        if(isCompleted()) {
            return responseJson;
        }
        return null;
    }

    /**
     * Prepare request body and headers. It's recommended to call this method on background
     * execution queue to avoid main thread disruptions.
     * <p>
     * If execution of this function fails, then the function will notify all its listeners.
     * @throws CoreException In case the operation fails.
     */
    public void prepareRequest() throws CoreException {
        try {
            prepareRequestImpl();
            failure = null;
        } catch (CoreException e) {
            failure = e;
            throw e;
        }
    }

    /**
     * Process response received from the server. It's recommended to call this method on background
     * execution queue to avoid main thread disruptions.
     * <p>
     * Function also notify all its listeners about successful or failure result of the call.
     * <p>
     * <b>Note:</b> Be aware that the method doesn't handle standard PowerAuth error response. You
     * suppose to call this method only if successful response is received from the server.
     *
     * @param response Response data received from the server.
     * @throws CoreException In case the operation fails.
     */
    public void processResponse(@Nullable byte[] response) throws CoreException {
        try {
            processResponseImpl(response);
            failure = null;
        } catch (CoreException e) {
            failure = e;
            throw e;
        }
    }

    /**
     * Cancel the request and release underlying resources. You have to call this method
     * when the operation is canceled by the application.
     */
    public native void cancel();

    /**
     * Set request as failed. You have to call this method when the HTTP request ends with
     * external failure, such as non-200 status code is received.
     * @param errorCode Error code to pass to C++ exception.
     * @param message Message to pass to the C++ exception.
     */
    private native void setFailed(@CoreErrorCode int errorCode, @Nullable String message);

    /**
     * Set request as failed. You have to call this method when the HTTP request ends with
     * external failure, such as non-200 status code is received.
     * @param failure External exception to keep in the response object.
     */
    public void setFailed(@Nullable Throwable failure) {
        if (failure != null && this.failure == null) {
            this.failure = failure;
        }
        @CoreErrorCode final int errorCode;
        if (failure instanceof CoreException) {
            errorCode = ((CoreException)failure).getErrorCode();
        } else {
            errorCode = CoreErrorCode.OTHER;
        }
        final String message = failure != null ? failure.getMessage() : null;
        setFailed(errorCode, message);
    }

    /**
     * Native request preparation function.
     * @throws CoreException In case the operation fails.
     */
    private native void prepareRequestImpl() throws CoreException;

    /**
     * Native response processing function.
     * @param response Response data.
     * @throws CoreException In case the operation fails.
     */
    private native void processResponseImpl(byte[] response) throws CoreException;
}
