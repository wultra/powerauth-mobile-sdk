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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.Logger;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class GroupedTaskTests {

    Executor backgroundExecutor;

    @Before
    public void setUp() {
        backgroundExecutor = Executors.newSingleThreadExecutor();
    }

    @Test
    public void testGroupedOperation() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        final Integer[] completionCounter = {0};
        final int expectedCompletion = 3;
        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        synchronized (this) {
                            completionCounter[0] = completionCounter[0] + 1;
                            if (completionCounter[0] == expectedCompletion) {
                                resultCatcher.completeWithSuccess();
                            }
                        }
                        assertTrue(aBoolean);
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        fail();
                    }
                };
                ICancelable childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);
                childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);
                childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);

                assertFalse(groupedTask.restart());

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        groupedTask.complete(true);
                    }
                });
            }
        });

        assertFalse(groupedTask.testOperation.isCancelled());
        assertEquals(expectedCompletion, completionCounter[0].intValue());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        ICancelable childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
        completionCounter[0] = 0;

        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        fail();
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        synchronized (this) {
                            completionCounter[0] = completionCounter[0] + 1;
                            if (completionCounter[0] == expectedCompletion) {
                                resultCatcher.completeWithSuccess();
                            }
                        }
                        assertEquals("Test failure", failure.getMessage());
                    }
                };
                ICancelable childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);
                childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);
                childTask = groupedTask.createChildTask(completion);
                assertNotNull(childTask);

                assertFalse(groupedTask.restart());

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        groupedTask.complete(new Exception("Test failure"));
                    }
                });
            }
        });

        assertFalse(groupedTask.testOperation.isCancelled());
        assertEquals(expectedCompletion, completionCounter[0].intValue());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
    }

    @Test
    public void testChildCancel() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        final Integer[] completionCounter = {0};
        final int expectedCompletion = 2;
        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        synchronized (this) {
                            completionCounter[0] = completionCounter[0] + 1;
                            if (completionCounter[0] == expectedCompletion) {
                                resultCatcher.completeWithSuccess();
                            }
                        }
                        assertTrue(aBoolean);
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        fail();
                    }
                };
                ICancelable childTask1 = groupedTask.createChildTask(completion);
                assertNotNull(childTask1);
                ICancelable childTask2 = groupedTask.createChildTask(completion);
                assertNotNull(childTask2);
                ICancelable childTask3 = groupedTask.createChildTask(completion);
                assertNotNull(childTask3);
                assertFalse(groupedTask.restart());

                childTask2.cancel();

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        groupedTask.complete(true);
                    }
                });
            }
        });

        assertFalse(groupedTask.testOperation.isCancelled());
        assertEquals(expectedCompletion, completionCounter[0].intValue());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        ICancelable childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
    }

    @Test
    public void testChildCancelAll() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        fail();
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        fail();
                    }
                };
                ICancelable childTask1 = groupedTask.createChildTask(completion);
                assertNotNull(childTask1);
                ICancelable childTask2 = groupedTask.createChildTask(completion);
                assertNotNull(childTask2);
                ICancelable childTask3 = groupedTask.createChildTask(completion);
                assertNotNull(childTask3);
                assertFalse(groupedTask.restart());

                childTask2.cancel();
                childTask1.cancel();
                childTask3.cancel();

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        resultCatcher.completeWithSuccess();
                    }
                });
            }
        });

        assertTrue(groupedTask.testOperation.isCancelled());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        ICancelable childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
    }

    @Test
    public void testChildCancelAllButContinue() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        groupedTask.taskShouldCancelWhenNoChildOperationIsSet = false;

        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                groupedTask.resultCatcher = resultCatcher;
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        fail();
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        fail();
                    }
                };
                ICancelable childTask1 = groupedTask.createChildTask(completion);
                assertNotNull(childTask1);
                ICancelable childTask2 = groupedTask.createChildTask(completion);
                assertNotNull(childTask2);
                ICancelable childTask3 = groupedTask.createChildTask(completion);
                assertNotNull(childTask3);
                assertFalse(groupedTask.restart());

                childTask2.cancel();
                childTask1.cancel();
                childTask3.cancel();

                ICancelable childTask4 = groupedTask.createChildTask(completion);
                assertNotNull(childTask4);
                childTask4.cancel();

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        groupedTask.complete(true);
                    }
                });
            }
        });

        assertFalse(groupedTask.testOperation.isCancelled());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        ICancelable childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
    }

    @Test
    public void testNoOperationAssigned() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        groupedTask.taskEvents = new ITestGroupedTaskEvents() {
            @Override
            public void onTaskStart(TestGroupedTask groupedTask) {
                Logger.d("Do nothing in task start");
            }

            @Override
            public void onTaskComplete(TestGroupedTask groupedTask) {
            }
        };

        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                groupedTask.resultCatcher = resultCatcher;
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        fail();
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        assertTrue(failure instanceof PowerAuthErrorException);
                        assertEquals(PowerAuthErrorCodes.OPERATION_CANCELED, ((PowerAuthErrorException) failure).getPowerAuthErrorCode());
                    }
                };
                ICancelable childTask1 = groupedTask.createChildTask(completion);
                assertNotNull(childTask1);
                ICancelable childTask2 = groupedTask.createChildTask(completion);
                assertNull(childTask2);
                ICancelable childTask3 = groupedTask.createChildTask(completion);
                assertNull(childTask3);
            }
        });

        assertNull(groupedTask.testOperation);
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);

        ICancelable childAfterComplete = groupedTask.createChildTask(new ITaskCompletion<Boolean>() {
            @Override
            public void onSuccess(@NonNull Boolean aBoolean) {
                fail();
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                fail();
            }
        });
        assertNull(childAfterComplete);
        assertTrue(groupedTask.restart());
    }

    @Test
    public void testReplaceOperation() throws Exception {
        final TestGroupedTask groupedTask = new TestGroupedTask();
        final TestOperationTask operation1 = new TestOperationTask();
        final TestOperationTask operation2 = new TestOperationTask();
        groupedTask.taskEvents = new ITestGroupedTaskEvents() {
            @Override
            public void onTaskStart(TestGroupedTask groupedTask) {
                groupedTask.addCancelableOperation(operation1);
            }

            @Override
            public void onTaskComplete(TestGroupedTask groupedTask) {
            }
        };

        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                ITaskCompletion<Boolean> completion = new ITaskCompletion<Boolean>() {
                    @Override
                    public void onSuccess(@NonNull Boolean aBoolean) {
                        fail();
                    }

                    @Override
                    public void onFailure(@NonNull Throwable failure) {
                        assertTrue(failure instanceof PowerAuthErrorException);
                        assertEquals(PowerAuthErrorCodes.OPERATION_CANCELED, ((PowerAuthErrorException) failure).getPowerAuthErrorCode());
                    }
                };
                ICancelable childTask1 = groupedTask.createChildTask(completion);
                assertNotNull(childTask1);
                ICancelable childTask2 = groupedTask.createChildTask(completion);
                assertNotNull(childTask2);
                ICancelable childTask3 = groupedTask.createChildTask(completion);
                assertNotNull(childTask3);

                backgroundExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        groupedTask.replaceCancelableOperation(operation2);
                        groupedTask.cancel();
                        backgroundExecutor.execute(new Runnable() {
                            @Override
                            public void run() {
                                backgroundExecutor.execute(new Runnable() {
                                    @Override
                                    public void run() {
                                        resultCatcher.completeWithSuccess();
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });

        assertNull(groupedTask.testOperation);
        assertFalse(operation1.isCancelled());
        assertTrue(operation2.isCancelled());
        assertEquals(1, groupedTask.monitorOnTaskStartCount);
        assertEquals(1, groupedTask.monitorOnTaskCompletionCount);
    }


    // Helper classes

    public interface ITestGroupedTaskEvents {
        void onTaskStart(TestGroupedTask groupedTask);
        void onTaskComplete(TestGroupedTask groupedTask);
    }

    public static class TestOperationTask implements ICancelable {
        private boolean canceled = false;
        @Override
        public void cancel() {
            canceled = true;
        }

        @Override
        public boolean isCancelled() {
            return canceled;
        }
    }

    public static class TestGroupedTask extends GroupedTask<Boolean> {

        // Configuration
        public boolean taskShouldCancelWhenNoChildOperationIsSet = true;
        public ITestGroupedTaskEvents taskEvents = null;
        public AsyncHelper.ResultCatcher<Void> resultCatcher = null;
        public ICancelable testOperation = null;

        // Monitors
        public int monitorOnTaskStartCount = 0;
        public int monitorOnTaskCompletionCount = 0;

        public TestGroupedTask() {
            super("TestGroupedTask", new ReentrantLock(), MainThreadExecutor.getInstance());
        }

        @Override
        public void onGroupedTaskStart() {
            super.onGroupedTaskStart();
            synchronized (this) {
                monitorOnTaskStartCount++;
            }
            if (taskEvents != null) {
                taskEvents.onTaskStart(this);
            } else {
                testOperation = new TestOperationTask();
                addCancelableOperation(testOperation);
            }
        }

        @Override
        public void onGroupedTaskRestart() {
            super.onGroupedTaskRestart();
            monitorOnTaskStartCount = 0;
            monitorOnTaskCompletionCount = 0;
            testOperation = null;
        }

        @Override
        public void onGroupedTaskComplete(@Nullable Boolean result, @Nullable Throwable failure) {
            super.onGroupedTaskComplete(result, failure);
            synchronized (this) {
                monitorOnTaskCompletionCount++;
            }
            if (taskEvents != null) {
                taskEvents.onTaskComplete(this);
            }
            if (resultCatcher != null) {
                resultCatcher.completeWithSuccess();
            }
        }

        @Override
        public boolean groupedTaskShouldCancelWhenNoChildOperationIsSet() {
            return taskShouldCancelWhenNoChildOperationIsSet;
        }
    }
}
