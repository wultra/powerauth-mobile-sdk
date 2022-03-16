/*
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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.core.EncryptedActivationStatus;
import io.getlime.security.powerauth.core.ErrorCode;
import io.getlime.security.powerauth.core.ProtocolUpgradeData;
import io.getlime.security.powerauth.core.ProtocolVersion;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SignatureUnlockKeys;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.endpoints.GetActivationStatusEndpoint;
import io.getlime.security.powerauth.networking.endpoints.UpgradeCommitV3Endpoint;
import io.getlime.security.powerauth.networking.endpoints.UpgradeStartV3Endpoint;
import io.getlime.security.powerauth.networking.endpoints.ValidateSignatureEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.networking.model.request.ValidateSignatureRequest;
import io.getlime.security.powerauth.networking.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.networking.model.response.UpgradeResponsePayload;
import io.getlime.security.powerauth.networking.response.IActivationStatusListener;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 *  The {@code GetActivationStatusTask} class implements getting activation status from the server
 *  and the protocol upgrade. The upgrade is started automatically, depending on the
 *  local and server's state of the activation.
 */
public class GetActivationStatusTask implements ICancelable {

    public interface ICompletionListener {
        void onSessionStateChange();
        void onSuccess(@NonNull GetActivationStatusTask task, @NonNull ActivationStatus status);
        void onFailure(@NonNull GetActivationStatusTask task);
    }

    private final HttpClient httpClient;
    private final Session session;
    private final IPrivateCryptoHelper cryptoHelper;
    private final ICompletionListener completionListener;
    private final ICallbackDispatcher callbackDispacher;

    private final AtomicBoolean isExiting = new AtomicBoolean();
    private final AtomicBoolean isCanceled = new AtomicBoolean();

    private final ArrayList<ChildTask> childTasks = new ArrayList<>();

    /**
     * Current pending operation.
     */
    private ICancelable pendingOperation;

    /**
     * @param httpClient HTTP client
     * @param cryptoHelper cryptographic helper
     * @param session low level {@link Session} object
     * @param callbackDispacher callback dispatcher from parent SDK object
     * @param completionListener final completion listener.
     */
    public GetActivationStatusTask(
            @NonNull HttpClient httpClient,
            @NonNull IPrivateCryptoHelper cryptoHelper,
            @NonNull Session session,
            @NonNull ICallbackDispatcher callbackDispacher,
            @NonNull ICompletionListener completionListener) {
        this.httpClient = httpClient;
        this.session = session;
        this.cryptoHelper = cryptoHelper;
        this.callbackDispacher = callbackDispacher;
        this.completionListener = completionListener;
        this.pendingOperation = null;
    }

    /**
     * If set to true, then the automatic protocol upgrade will not start.
     */
    private boolean isUpgradeDisabled;

    /**
     * @return true if automatic upgrade is disabled.
     */
    public boolean isUpgradeDisabled() {
        return isUpgradeDisabled;
    }

    /**
     * Enable or disable automatic protocol upgrade.
     *
     * @param upgradeDisabled Set true, if automatic upgrade should be disabled.
     */
    public void setUpgradeDisabled(boolean upgradeDisabled) {
        isUpgradeDisabled = upgradeDisabled;
    }

    /**
     * true if execute() method has been called
     */
    private boolean isStarted = false;

    /**
     * Start this task.
     */
    public void execute() {
        if (isStarted) {
             return;
        }
        isStarted = true;
        lastFetchedStatus = null;
        protocolUpgradeAttempts = 3;
        fetchActivationStatusAndTestUpgrade();
    }


    //
    // Fetch status
    //

    /**
     * Fetch activation status from the server and test whether the protocol upgrade is available
     * or not. If upgrade is available, then upgrade the session.
     */
    private void fetchActivationStatusAndTestUpgrade() {
        fetchActivationStatus(new IActivationStatusListener() {
            @Override
            public void onActivationStatusSucceed(ActivationStatus status) {
                // Test whether we have to serialize session's persistent data.
                if (status.needsSerializeSessionState) {
                    serializeSessionState();
                }
                // We have status. Test for protocol upgrade.
                if (status.isUpgradeAvailable || session.hasPendingProtocolUpgrade()) {
                    if (!isUpgradeDisabled) {
                        // If upgrade is available, or is pending, then simply switch
                        // to the upgrade code, which will handle all other cases.
                        continueWithUpgrade(status);
                        return;
                    }
                    PowerAuthLog.e("WARNING: Upgrade to newer protocol version is disabled.");
                }
                // Now test whether the counter should be synchronized on the server.
                if (status.isSignatureCalculationRecommended) {
                    synchronizeCounter(status);
                    return;
                }
                // Otherwise return the result as usual
                completeTask(status, null);
            }

            @Override
            public void onActivationStatusFailed(@NonNull Throwable t) {
                // In case of error, just complete the task with error.
                completeTask(null, t);
            }
        });
    }

    /**
     * Fetch activation status from the server. This is the low level operation, which simply
     * receives the status from the server and does no additional processing.
     *
     * @param listener listener to be called with the result
     */
    private void fetchActivationStatus(@NonNull final IActivationStatusListener listener) {

        // Execute request
        final ActivationStatusRequest request = new ActivationStatusRequest();
        request.setActivationId(session.getActivationIdentifier());
        request.setChallenge(session.generateActivationStatusChallenge());

        pendingOperation = httpClient.post(
                request,
                new GetActivationStatusEndpoint(),
                cryptoHelper,
                new INetworkResponseListener<ActivationStatusResponse>() {
                    @Override
                    public void onNetworkResponse(@NonNull ActivationStatusResponse response) {
                        // Network communication completed correctly
                        pendingOperation = null;
                        // Prepare object with encryped status
                        final EncryptedActivationStatus encryptedStatus = new EncryptedActivationStatus(request.getChallenge(), response.getEncryptedStatusBlob(), response.getNonce());
                        // Prepare unlocking key (possession factor only)
                        final SignatureUnlockKeys keys = new SignatureUnlockKeys(cryptoHelper.getDeviceRelatedKey(), null, null);
                        // Attempt to decode the activation status
                        final ActivationStatus activationStatus = session.decodeActivationStatus(encryptedStatus, keys);
                        if (activationStatus != null) {
                            // Everything was OK, keep custom object and report that result.
                            activationStatus.setCustomObject(response.getCustomObject());
                            listener.onActivationStatusSucceed(activationStatus);
                        } else {
                            // Error occurred when decoding status
                            listener.onActivationStatusFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA));
                        }
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable t) {
                        pendingOperation = null;
                        listener.onActivationStatusFailed(t);
                    }

                    @Override
                    public void onCancel() {
                        pendingOperation = null;
                    }
                });
    }

    //
    // Counter synchronization
    //

    /**
     * Continue task with signature counter synchronization. In this case, just {@code /pa/signature/validate}
     * endpoint is called, with simple possession-only signature. That will force server to catch up
     * with the local counter.
     *
     * @param status {@link ActivationStatus} reported in case of success.
     */
    private void synchronizeCounter(@NonNull final ActivationStatus status) {

        // Authenticate with possession factor.
        final PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.usePossession = true;

        // Execute signature validation request
        final ValidateSignatureRequest request = new ValidateSignatureRequest();
        request.setReason("COUNTER_SYNCHRONIZATION");

        pendingOperation = httpClient.post(
                request,
                new ValidateSignatureEndpoint(),
                cryptoHelper,
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(@NonNull Void aVoid) {
                        pendingOperation = null;
                        completeTask(status, null);
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        pendingOperation = null;
                        completeTask(null, throwable);
                    }

                    @Override
                    public void onCancel() {
                        pendingOperation = null;
                    }
                }

        );
    }


    //
    // Protocol upgrade
    //

    private void serializeSessionState() {
        completionListener.onSessionStateChange();
    }

    /**
     * Contains last fetched status, for later reporting.
     */
    private ActivationStatus lastFetchedStatus;
    /**
     * Contains number of attempts available for the upgrade. The upgrade procedure is will try
     * to finish the job in case that some partial operation fails.
     */
    private int protocolUpgradeAttempts;


    /**
     * Continue task with the protocol upgrade. This is the "main" function, which handles
     * all possible combination of upgrade states, so it's safe to call it when the status
     * is known.
     *
     * @param status last received activation status
     */
    private void continueWithUpgrade(@NonNull ActivationStatus status) {

        // Keep status for later processing
        lastFetchedStatus = status;

        // Check whether we reached maximum attempts for upgrade
        if (protocolUpgradeAttempts-- > 0) {
            // Simply continue to V3 upgrade
            continueWithUpgradeToV3(status);
        } else {
            final Throwable error = new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Number of upgrade attempts reached its maximum.");
            completeTask(null, error);
        }
    }

    /**
     * Continue task with the protocol V3 upgrade.
     *
     * @param status last received activation status
     */
    private void continueWithUpgradeToV3(@NonNull ActivationStatus status) {

        // Keep status for later processing
        lastFetchedStatus = status;

        // Get server's and ours protocol version.
        final ProtocolVersion serverVersion = status.currentVersion;
        final ProtocolVersion localVersion = session.getProtocolVersion();

        if (serverVersion == ProtocolVersion.V2) {

            // Server is still on V2 version, so we need to determine how to continue.
            // At first, we should check whether the upgrade was started, because this
            // continue method must handle all possible upgrade states.

            if (session.getPendingProtocolUpgradeVersion() == ProtocolVersion.NA) {
                // Upgrade has not been started yet
                PowerAuthLog.d("ProtocolUpgrade: Starting activation upgrade to protocol V3");
                if (session.startProtocolUpgrade() != ErrorCode.OK) {
                    completeTaskWithUpgradeError("Protocol upgrade start failed.");
                    return;
                }
                serializeSessionState();
            }

            // Now lets test the current local protocol version
            if (localVersion == ProtocolVersion.V2) {
                // Looks like we didn't start upgrade on the server, or the request
                // didn't finish. In other words, we still don't have the CTR_DATA locally.
                startUpgradeToV3();
                return;

            } else if (localVersion == ProtocolVersion.V3) {
                // We already have CTR_DATA, but looks like server didn't receive our "commit" message.
                // This is because server's version is still in V2.
                commitUpgradeToV3();
                return;
            }

            // Current local version is unknown. This should never happen, unless there's
            // a new protocol version and upgrade routine is not updated.
            // This branch will report "Internal upgrade error"

        } else if (serverVersion == ProtocolVersion.V3) {

            // Server is already on V3 version, check the local version.

            if (localVersion == ProtocolVersion.V2) {
                // This makes no sense. Server is in V3, but the client is still in V2.
                // Only possible explanation is that local session has been restored from some
                // older backup. For all cases, it's recommended to reset the session.
                completeTaskWithUpgradeError("Server-Client protocol version mishmash.");
                return;

            } else if (localVersion == ProtocolVersion.V3) {
                // Server is in V3, local version is in V3
                final ProtocolVersion pendingUpgradeVersion = session.getPendingProtocolUpgradeVersion();
                if (pendingUpgradeVersion == ProtocolVersion.V3) {
                    // Looks like we need to just finish the upgrade. Server and our local session
                    // are already on V3, but pending flag indicates, that we're still in the process.
                    finishUpgradeToV3();
                    return;

                } else if (pendingUpgradeVersion == ProtocolVersion.NA) {
                    // Server's in V3, client's in V3, no pending upgrade.
                    // This is weird, but we can just report the result.
                    completeTask(lastFetchedStatus, null);
                    return;
                }
            }

            // Current local version is unknown. This should never happen, unless there's
            // a new protocol version and upgrade routine is not updated.
            // This branch will also report "Internal upgrade error"

        } else {

            // Server's version is unknown.
            completeTaskWithUpgradeError("Unknown server version.");
            return;
        }

        // For all other cases, report the internal error.
        completeTaskWithUpgradeError("Internal protocol upgrade error.");
    }


    /**
     * Starts upgrade to V3 on the server.
     */
    private void startUpgradeToV3() {
        pendingOperation = httpClient.post(
                null,
                new UpgradeStartV3Endpoint(),
                cryptoHelper,
                new INetworkResponseListener<UpgradeResponsePayload>() {
                    @Override
                    public void onNetworkResponse(@NonNull UpgradeResponsePayload response) {
                        // Http request succeeded.
                        pendingOperation = null;
                        // Prepare and apply the upgrade data.
                        final ProtocolUpgradeData upgradeData = ProtocolUpgradeData.version3(response.getCtrData());
                        if (session.applyProtocolUpgradeData(upgradeData) == ErrorCode.OK) {
                            // Everything looks fine, we can continue with commit on server.
                            // Since this change, we can sign requests with V3 signatures
                            // and local protocol version is bumped to V3.
                            serializeSessionState();
                            commitUpgradeToV3();
                        } else {
                            // The low level session did reject the data
                            completeTaskWithUpgradeError("Failed to apply upgrade data.");
                        }
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        // In case of error, try to repeat the operation
                        pendingOperation = null;
                        fetchActivationStatusAndTestUpgrade();
                    }

                    @Override
                    public void onCancel() {
                        pendingOperation = null;
                    }
                });
    }

    /**
     * Commits upgrade to V3 on the server.
     */
    private void commitUpgradeToV3() {
        // Prepare auth object with possession factor.
        PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.usePossession = true;
        // Start HTTP request
        pendingOperation = httpClient.post(
                null,
                new UpgradeCommitV3Endpoint(),
                cryptoHelper,
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(@NonNull Void o) {
                        // Http request succeeded.
                        pendingOperation = null;
                        // Everything looks fine, just finish the operation
                        finishUpgradeToV3();
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        // In case of error, try to repeat the operation
                        pendingOperation = null;
                        fetchActivationStatusAndTestUpgrade();
                    }

                    @Override
                    public void onCancel() {
                        pendingOperation = null;
                    }
                });
    }

    /**
     * Completes the whole upgrade process locally.
     */
    private void finishUpgradeToV3() {
        // Try to complete the process
        if (session.finishProtocolUpgrade() == ErrorCode.OK) {
            PowerAuthLog.d("ProtocolUpgrade: Activation was successfully upgraded to protocol V3.");
            // Everything looks fine, we can report previously cached status
            serializeSessionState();
            completeTask(lastFetchedStatus, null);
        } else {
            // Unfortunately, session did reject the upgrade completion.
            completeTaskWithUpgradeError("Failed to complete the upgrade process.");
        }
    }


    //
    // Cancelable
    //

    @Override
    public void cancel() {
        isCanceled.set(true);
        synchronized (this) {
            if (pendingOperation != null) {
                pendingOperation.cancel();
                pendingOperation = null;
            }
        }
        // Report "cancel from elsewhere"
        completeTask(null, null);
    }

    @Override
    public boolean isCancelled() {
        return isCanceled.get();
    }


    //
    // Task completion
    //

    /**
     * Complete the task with status or with error. If both objects are not provided, then the
     * {@link PowerAuthErrorCodes#OPERATION_CANCELED} exception is created.
     *
     * @param status status to be reported
     * @param throwable error to be reported
     */
    private void completeTask(@Nullable ActivationStatus status, @Nullable Throwable throwable) {

        if (isExiting.getAndSet(true)) {
            // We're already exiting
            return;
        }

        // If both parameters are null, then it's
        if (status == null && throwable == null) {
            throwable = new PowerAuthErrorException(PowerAuthErrorCodes.OPERATION_CANCELED, "Operation was canceled from elsewhere.");
        }

        final ArrayList<ChildTask> tasksToReport;
        synchronized (this) {
            tasksToReport = new ArrayList<>(childTasks);
            childTasks.clear();
        }

        // At first, report to primary listener (e.g. to the PowerAuthSDK)
        if (status != null) {
            completionListener.onSuccess(this, status);
        } else {
            completionListener.onFailure(this);
        }
        // Now report to all child tasks
        for (ChildTask task : tasksToReport) {
            task.complete(status, throwable);
        }
    }


    /**
     * Complete task with {@link PowerAuthErrorException} and with {@link PowerAuthErrorCodes#PROTOCOL_UPGRADE}
     * error code.
     *
     * @param message additional message describing the reason why the task failed.
     */
    private void completeTaskWithUpgradeError(@NonNull String message) {
        completeTask(null, new PowerAuthErrorException(PowerAuthErrorCodes.PROTOCOL_UPGRADE, message));
    }


    //
    // Child task
    //

    /**
     * Add a listener into the list of listeners for later completion. The method returns {@link ICancelable}
     * object capturing the listener provided to the function. The application can cancel the returned
     * object. After that, the listener will never be completed.
     *
     * @param listener {@link IActivationStatusListener} to be added to the list of completion listeners
     * @return {@link ICancelable} object capturing the listener or null if this task is already exiting.
     */
    public @Nullable ICancelable addActivationStatusListener(@NonNull IActivationStatusListener listener) {
        synchronized (this) {
            if (!isExiting.get()) {
                final ChildTask task = new ChildTask(listener);
                childTasks.add(task);
                return task;
            }
            return null;
        }
    }


    /**
     * Remove one particular child task from list of child tasks. The method should be used
     * only from {@link ChildTask#cancel()} method.
     *
     * @param task child task to be removed
     */
    private void removeActivationStatusListener(@NonNull ChildTask task) {
        synchronized (this) {
            childTasks.remove(task);
        }
    }


    /**
     * The {@code ChildTask} class wraps one {@link IActivationStatusListener} listener into
     * cancelable object. The application can then cancel its previously created request for
     * the activation status.
     */
    private class ChildTask implements ICancelable {

        private final IActivationStatusListener listener;
        private final AtomicBoolean isCanceled = new AtomicBoolean();

        ChildTask(@NonNull IActivationStatusListener listener) {
            this.listener = listener;
        }

        @Override
        public void cancel() {
            isCanceled.set(true);
            removeActivationStatusListener(this);
        }

        @Override
        public boolean isCancelled() {
            return isCanceled.get();
        }

        /**
         * Notify listener about the result.
         *
         * @param status if not null, then the {@link IActivationStatusListener#onActivationStatusSucceed(ActivationStatus)} will be called
         * @param throwable if not null, then the {@link IActivationStatusListener#onActivationStatusFailed(Throwable)} will be called
         */
        public void complete(final @Nullable ActivationStatus status, final @Nullable Throwable throwable) {
            if (!isCanceled.getAndSet(true)) {
                callbackDispacher.dispatchCallback(new Runnable() {
                    @Override
                    public void run() {
                        if (status != null) {
                            listener.onActivationStatusSucceed(status);
                        } else {
                            listener.onActivationStatusFailed(throwable);
                        }
                    }
                });
            }
        }
    }
}
