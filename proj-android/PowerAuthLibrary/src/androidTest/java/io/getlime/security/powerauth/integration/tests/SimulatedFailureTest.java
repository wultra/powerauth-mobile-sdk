/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.annotation.NonNull;

import org.junit.Test;

import java.util.function.Function;

import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;

/**
 * Test of handling failures in communication with the server.
 */
public class SimulatedFailureTest extends BaseTest {

    @Override
    public void setUp() throws Exception {
        super.setUp();
        assertTrue(isRequestFailureSimulatorAvailable());
    }

    /**
     * This test validates whether HTTP response failure simulation works properly.
     */
    @Test
    public void testSimulatedHttpResponseFailure() throws Exception {
        final Function<AsyncHelper.ResultCatcher<Boolean>, IServerStatusListener> listener = (resultCatcher) -> new IServerStatusListener() {
            @Override
            public void onServerStatusSucceeded(@NonNull ServerStatus status) {
                resultCatcher.completeWithResult(true);
            }

            @Override
            public void onServerStatusFailed(@NonNull Throwable t) {
                resultCatcher.completeWithResult(false);
            }
        };

        simulateNextResponseFailure("/status", 500);
        boolean succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertFalse(succeeded);

        simulateNextResponseFailure("/status", 500);
        simulateNetworkErrorOnSend(null);
        simulateNetworkErrorOnReceive("*");
        clearAllSimulateFailures();
        succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertTrue(succeeded);

        simulateNextResponseFailure("*", 500);
        succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertFalse(succeeded);

        simulateNetworkErrorOnSend(null, 2);
        succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertFalse(succeeded);

        succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertFalse(succeeded);

        succeeded = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchServerStatus(listener.apply(resultCatcher))
        );
        assertTrue(succeeded);
    }

}
