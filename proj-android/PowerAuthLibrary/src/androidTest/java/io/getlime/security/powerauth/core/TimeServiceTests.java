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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.model.response.ServerStatusResponse;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;
import io.getlime.security.powerauth.sdk.impl.DefaultServerStatusProvider;
import io.getlime.security.powerauth.sdk.impl.IServerStatusProvider;
import io.getlime.security.powerauth.sdk.impl.TimeSynchronizationService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Random;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TimeServiceTests {

    TimeSynchronizationService timeService;
    TestTimeProvider timeProvider;

    @Before
    public void setUp() {
        timeProvider = new TestTimeProvider(T_EPSILON);
        timeService = new TimeSynchronizationService(timeProvider, new TestSystemStatusProvider(timeProvider), Runnable::run);
    }

    @Test
    public void testTimeSynchronization() throws Exception {
        assertFalse(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());
        assertTrue(timeIntervalIsEqual(date(), timeService.getCurrentTime()));

        Object task = timeService.startTimeSynchronizationTask();
        sleep(10);
        long serverTime = date();
        sleep(10);
        boolean result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment()); // no adjustment, difference is too small

        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date() + 5000; // 5 seconds ahead, too small to be accepted
        sleep(10);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());

        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date() - 5000; // 5 seconds behind, too small to be accepted
        sleep(10);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());

        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date() + 30_000;
        sleep(10);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertTrue(timeIntervalInRange(timeService.getLocalTimeAdjustment(), 29_900, 30_100));
        assertTrue(timeIntervalInRange(timeService.getCurrentTime() - date(), 29_900, 30_100));

        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date() - 30_000;
        sleep(10);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertTrue(timeIntervalInRange(timeService.getLocalTimeAdjustment(), -30_100, -29_900));
        assertTrue(timeIntervalInRange(timeService.getCurrentTime() - date(), -30_100, -29_900));

        // Repeat the task, that we can test filter for time fluctuation
        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date() - 32_000;
        sleep(10);
        long prevAdjustment = timeService.getLocalTimeAdjustment();
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        // Adjustment should be exactly equal to previous one.
        assertEquals(prevAdjustment, timeService.getLocalTimeAdjustment());

        task = timeService.startTimeSynchronizationTask();
        sleep(10);
        serverTime = date();        // go back to normal
        sleep(10);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertTrue(timeIntervalInRange(timeService.getLocalTimeAdjustment(), -100, 100));
        assertTrue(timeIntervalInRange(timeService.getCurrentTime() - date(), -100, 100));

        timeService.resetTimeSynchronization();
        assertFalse(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());
    }

    @Test
    public void testTooLongTimeSynchronization() throws Exception {
        assertFalse(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());
        assertTrue(timeIntervalIsEqual(date(), timeService.getCurrentTime()));

        Object task = timeService.startTimeSynchronizationTask();
        sleep(5000);
        long serverTime = date();
        sleep(5000);
        boolean result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());

        task = timeService.startTimeSynchronizationTask();
        sleep(100);
        serverTime = date();
        sleep(15_000);
        // took too long to complete, but service is already synchronized
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertTrue(result);
        assertTrue(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());

        timeService.resetTimeSynchronization();

        task = timeService.startTimeSynchronizationTask();
        sleep(6_000);
        serverTime = date();
        sleep(15_000);
        result = timeService.completeTimeSynchronizationTask(task, serverTime);
        assertFalse(result);
        assertFalse(timeService.isTimeSynchronized());
        assertEquals(0L, timeService.getLocalTimeAdjustment());
    }

    @Test
    public void testWrongTasks() throws Exception
    {
        assertFalse(timeService.completeTimeSynchronizationTask("BAD", date()));
        assertFalse(timeService.completeTimeSynchronizationTask(3.14, date()));
        assertFalse(timeService.completeTimeSynchronizationTask(null, date()));
        assertFalse(timeService.completeTimeSynchronizationTask(date() + 1000, date()));
    }

    // Helper classes and functions

    static class TestTimeProvider implements TimeSynchronizationService.ITimeProvider {
        private final int maxRandomSleep;
        private final Random random = new Random();
        private long currentTime = System.currentTimeMillis();

        TestTimeProvider(int maxRandomSleep) {
            this.maxRandomSleep = maxRandomSleep;
        }

        @Override
        public long getCurrentTime() {
            return currentTime;
        }

        void sleep(long interval) {
            currentTime += random.nextInt(maxRandomSleep);
            currentTime += interval;
        }
    }

    static class TestSystemStatusProvider implements IServerStatusProvider {
        private final TimeSynchronizationService.ITimeProvider timeProvider;

        TestSystemStatusProvider(TimeSynchronizationService.ITimeProvider timeProvider) {
            this.timeProvider = timeProvider;
        }

        @Nullable
        @Override
        public ICancelable getServerStatus(@NonNull IServerStatusListener listener) {
            final ServerStatusResponse response = new ServerStatusResponse();
            response.setServerTime(timeProvider.getCurrentTime());
            listener.onServerStatusSucceeded(new ServerStatus(response));
            return new ICancelable() {
                private boolean isCanceled = false;
                @Override
                public void cancel() {
                    isCanceled = true;
                }

                @Override
                public boolean isCancelled() {
                    return isCanceled;
                }
            };
        }
    }

    void sleep(long interval) {
        timeProvider.sleep(interval);
    }

    long date() {
        return timeProvider.getCurrentTime();
    }

    final int T_EPSILON = 100;

    boolean timeIntervalIsEqual(long a, long b) {
        return Math.abs(a - b) < T_EPSILON;
    }

    boolean timeIntervalInRange(long t, long min, long max) {
        return (t > min - T_EPSILON) && (t < max + T_EPSILON);
    }
}
