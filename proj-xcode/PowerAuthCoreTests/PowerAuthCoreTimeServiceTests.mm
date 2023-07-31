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

#import <XCTest/XCTest.h>
#import <PowerAuthCore/PowerAuthCore.h>

#pragma mark - Helpers

static BOOL DoubleIsEqual(double a, double b, double epsilon)
{
    return fabs(a - b) < epsilon;
}

const double T_epsilon = 1e-5;

static BOOL TimeIntervalIsEqual(NSTimeInterval a, NSTimeInterval b)
{
    return DoubleIsEqual(a, b, T_epsilon);   // 10us
}

static BOOL TimeIntervalInRange(NSTimeInterval t, double min, double max)
{
    return (t > min - T_epsilon) && (t < max + T_epsilon);
}

// Test time provider

static NSTimeInterval testTime = 0;

static void SleepThread(NSTimeInterval interval)
{
    // add a random value to make the time advance real.
    testTime += ((double)arc4random_uniform(1000)) * 0.0001;
    testTime += interval;
}

static NSTimeInterval Date(void)
{
    return testTime;
}

static void ResetDate()
{
    testTime = [[NSDate date] timeIntervalSince1970];
}

@interface PowerAuthCoreTimeService (Private)
// Expose internal interface available in DEBUG build to alter the time provider.
// Use NULL to reset to actual time.
- (void) setTestTimeProvider:(NSTimeInterval (*)(void))timeProviderFunc;
@end

#pragma mark - Test

@interface PowerAuthCoreTimeServiceTests : XCTestCase
@end

@implementation PowerAuthCoreTimeServiceTests
{
    PowerAuthCoreTimeService * service;
}

- (void) setUp
{
    [super setUp];
    PowerAuthCoreLogSetEnabled(YES);
    ResetDate();
    service = [PowerAuthCoreTimeService sharedInstance];
    [service setTestTimeProvider:Date]; // Set to our test date provider
    [service resetTimeSynchronization];
}

- (void) tearDown
{
    [super tearDown];
    // Reset internal time providing function back to normal.
    [service setTestTimeProvider:NULL];
}

- (void) testTimeSynchronization
{
    XCTAssertFalse(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
    XCTAssertTrue(TimeIntervalIsEqual(Date(), service.currentTime));
    
    id task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    NSTimeInterval serverTime = Date() * 1000.0;
    SleepThread(0.01);  // 10ms
    BOOL result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    
    XCTAssertTrue(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);   // no adjustment, difference is too small

    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date() + 5.0) * 1000.0;              // 5 seconds ahead, too small to be accepted
    SleepThread(0.01);  // 10ms
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);

    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date() - 5.0) * 1000.0;              // 5 seconds behind, too small to be accepted
    SleepThread(0.01);  // 10ms
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
    
    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date() + 30.0) * 1000.0;              // 30 seconds ahead
    SleepThread(0.01);  // 10ms
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    NSLog(@"Time adjustment %lf", service.localTimeAdjustment);
    XCTAssertTrue(TimeIntervalInRange(service.localTimeAdjustment, 29.9, 30.1));
    XCTAssertTrue(TimeIntervalInRange(service.currentTime - Date(), 29.9, 30.1));

    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date() - 30.0) * 1000.0;              // 30 seconds behind
    SleepThread(0.01);  // 10ms
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    NSLog(@"Time adjustment %lf", service.localTimeAdjustment);
    XCTAssertTrue(TimeIntervalInRange(service.localTimeAdjustment, -30.1, -29.9));
    XCTAssertTrue(TimeIntervalInRange(service.currentTime - Date(), -30.1, -29.9));

    // Repeat the task, that we can test filter for time fluctuation
    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date() - 32.0) * 1000.0;              // 30 seconds behind
    SleepThread(0.01);  // 10ms
    NSTimeInterval prevAdjustment = service.localTimeAdjustment;
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    // Adjustment should be exactly equal to previous one.
    XCTAssertEqual(prevAdjustment, service.localTimeAdjustment);

    task = [service startTimeSynchronizationTask];
    SleepThread(0.01);  // 10ms
    serverTime = (Date()) * 1000.0;                     // go back to normal
    SleepThread(0.01);  // 10ms
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    NSLog(@"Time adjustment %lf", service.localTimeAdjustment);
    XCTAssertTrue(TimeIntervalInRange(service.localTimeAdjustment, -0.1, 0.1));
    XCTAssertTrue(TimeIntervalInRange(service.currentTime - Date(), -0.1, 0.1));
    
    [service resetTimeSynchronization];
    XCTAssertFalse(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
}

- (void) testTooLongTimeSynchronization
{
    XCTAssertFalse(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
    XCTAssertTrue(TimeIntervalIsEqual(Date(), service.currentTime));

    id task = [service startTimeSynchronizationTask];
    SleepThread(5.00);  // 5ms
    NSTimeInterval serverTime = (Date() + 0.0) * 1000.0;              // No difference
    SleepThread(5.00);  // 5ms
    BOOL result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
        
    task = [service startTimeSynchronizationTask];
    SleepThread(0.10);  // 100ms
    serverTime = (Date() + 0.0) * 1000.0;              // No difference
    SleepThread(15.00);  // 10s
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertTrue(result);
    XCTAssertTrue(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);  // no change against last attempt
    
    [service resetTimeSynchronization];
    
    task = [service startTimeSynchronizationTask];
    SleepThread(6.0);  // 100ms
    serverTime = (Date() + 0.0) * 1000.0;              // No difference against real time
    SleepThread(11.00);  // 10s
    result = [service completeTimeSynchronizationTask:task withServerTime:serverTime];
    XCTAssertFalse(result);
    XCTAssertFalse(service.isTimeSynchronized);
    XCTAssertEqual(0.0, service.localTimeAdjustment);
}

- (void) testWrongTasks
{
    XCTAssertFalse([service completeTimeSynchronizationTask:@"BAD" withServerTime:Date()]);
    XCTAssertFalse([service completeTimeSynchronizationTask:nil withServerTime:Date()]);
    XCTAssertFalse([service completeTimeSynchronizationTask:@((NSInteger)10) withServerTime:Date()]);
    XCTAssertFalse([service completeTimeSynchronizationTask:@(Date() + 10) withServerTime:Date()]);
}

@end
