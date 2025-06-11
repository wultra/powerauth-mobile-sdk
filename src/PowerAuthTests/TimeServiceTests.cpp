/*
 * Copyright 2021 Wultra s.r.o.
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

#include <cc7tests/CC7Tests.h>
#include <PowerAuth/TimeService.h>
#include "TestTimeProvider.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

// Unit test

class TimeServiceTests : public UnitTest
{
public:
    
    TimeServiceTests()
    {
        CC7_REGISTER_TEST_METHOD(testTimeSynchronization)
        CC7_REGISTER_TEST_METHOD(testTooLongTimeSynchronization)
        CC7_REGISTER_TEST_METHOD(testWrongTask)
    }
    
    std::shared_ptr<TestTimeProvider> provider;
    TimeServicePtr servicePtr;
    
    void setUp() override
    {
        provider = std::make_shared<TestTimeProvider>();
        servicePtr = std::make_shared<TimeService>(provider);
    }
    
    void SleepThread(TimeInterval interval)
    {
        // add a random value to make the time advance real.
        provider->sleepThread(interval);
    }

    TimeInterval Date(void)
    {
        return provider->getCurrentTime();
    }

    void ResetDate(void)
    {
        provider->setTime(cc7::GetCurrentTime());
    }

    
    void testTimeSynchronization()
    {
        auto& service = *servicePtr;
        
        ccstAssertFalse(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
        ccstAssertTrue(TimeIntervalIsEqual(Date(), service.currentTime()));
        
        auto task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        auto serverTime = Date();
        SleepThread(0.01);  // 10ms
        auto result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        
        ccstAssertTrue(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());   // no adjustment, difference is too small

        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date() + 5.0);                        // 5 seconds ahead, too small to be accepted
        SleepThread(0.01);  // 10ms
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());

        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date() - 5.0)         ;               // 5 seconds behind, too small to be accepted
        SleepThread(0.01);  // 10ms
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
        
        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date() + 30.0);                       // 30 seconds ahead
        SleepThread(0.01);  // 10ms
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstMessage("Time adjustment %lf", service.localTimeAdjustment());
        ccstAssertTrue(TimeIntervalInRange(service.localTimeAdjustment(), 29.9, 30.1));
        ccstAssertTrue(TimeIntervalInRange(service.currentTime() - Date(), 29.9, 30.1));

        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date() - 30.0);                       // 30 seconds behind
        SleepThread(0.01);  // 10ms
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstMessage("Time adjustment %lf", service.localTimeAdjustment());
        ccstAssertTrue(TimeIntervalInRange(service.localTimeAdjustment(), -30.1, -29.9));
        ccstAssertTrue(TimeIntervalInRange(service.currentTime() - Date(), -30.1, -29.9));

        // Repeat the task, that we can test filter for time fluctuation
        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date() - 32.0);                       // 30 seconds behind
        SleepThread(0.01);  // 10ms
        auto prevAdjustment = service.localTimeAdjustment();
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        // Adjustment should be exactly equal to previous one.
        ccstAssertEqual(prevAdjustment, service.localTimeAdjustment());

        task = service.startTimeSynchronizationTask();
        SleepThread(0.01);  // 10ms
        serverTime = (Date());                              // go back to normal
        SleepThread(0.01);  // 10ms
        result = service.completeTimeSynchronizationTask(task,serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstMessage("Time adjustment %lf", service.localTimeAdjustment());
        ccstAssertTrue(TimeIntervalInRange(service.localTimeAdjustment(), -0.1, 0.1));
        ccstAssertTrue(TimeIntervalInRange(service.currentTime() - Date(), -0.1, 0.1));
        
        service.resetTimeSynchronization();
        ccstAssertFalse(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
    }
    
    void testTooLongTimeSynchronization()
    {
        auto& service = *servicePtr;
        
        ccstAssertFalse(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
        ccstAssertTrue(TimeIntervalIsEqual(Date(), service.currentTime()));

        auto task = service.startTimeSynchronizationTask();
        SleepThread(5.00);  // 5ms
        auto serverTime = (Date() + 0.0);             // No difference
        SleepThread(5.00);  // 5ms
        auto result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
            
        task = service.startTimeSynchronizationTask();
        SleepThread(0.10);  // 100ms
        serverTime = (Date() + 0.0);                            // No difference
        SleepThread(15.00);  // 10s
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertTrue(result);
        ccstAssertTrue(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());  // no change against last attempt
        
        service.resetTimeSynchronization();
        
        task = service.startTimeSynchronizationTask();
        SleepThread(6.0);  // 100ms
        serverTime = (Date() + 0.0);                            // No difference against real time
        SleepThread(11.00);  // 10s
        result = service.completeTimeSynchronizationTask(task, serverTime);
        ccstAssertFalse(result);
        ccstAssertFalse(service.isTimeSynchronized());
        ccstAssertEqual(0.0, service.localTimeAdjustment());
    }

    void testWrongTask()
    {
        auto& service = *servicePtr;
        ccstAssertFalse(service.completeTimeSynchronizationTask(-100, Date()));
    }
};

CC7_CREATE_UNIT_TEST(TimeServiceTests, "pa2")
    
} // namespace powerAuthTests
