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

#import <XCTest/XCTest.h>
#import <PowerAuth2/PowerAuthLog.h>
#import <PowerAuthCore/PowerAuthCore.h>

@interface PA2LogCollector : NSObject<PowerAuthLogDelegate>
@property (nonatomic, readonly) NSArray<NSString*> * messages;
@property (nonatomic, copy) void (^onLog)(NSString * message);
- (void) clear;
@end

@implementation PA2LogCollector
{
    NSMutableArray<NSString*> * _messages;
}

- (instancetype) init
{
    self = [super init];
    if (self) {
        _messages = [NSMutableArray array];
    }
    return self;
}

- (void) powerAuthLog:(NSString*)message
{
    @synchronized (_messages) {
        [_messages addObject:message];
    }
    if (_onLog) {
        _onLog(message);
    }
}

- (NSArray<NSString*>*) messages
{
    @synchronized (_messages) {
        return [_messages copy];
    }
}

- (void) clear
{
    @synchronized (_messages) {
        [_messages removeAllObjects];
    }
}

@end

static NSString * const NativeTimeLog = @"[cc7] TimeService: Time is no longer synchronized";

@interface PowerAuthLogTests : XCTestCase
@end

@implementation PowerAuthLogTests
{
    PA2LogCollector * _collector;
    PowerAuthCoreSession * _session;
    BOOL _savedEnabled;
    BOOL _savedVerbose;
    BOOL _savedConsole;
}

- (void) setUp
{
    [super setUp];
    _savedEnabled = PowerAuthLogIsEnabled();
    _savedVerbose = PowerAuthLogIsVerbose();
    _savedConsole = PowerAuthLogToConsoleIsEnabled();
    _collector = [[PA2LogCollector alloc] init];
    PowerAuthLogSetDelegate(_collector);
    PowerAuthLogToConsoleSetEnabled(NO);
    NSString * configuration = @"ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4"
                                @"oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==";
    NSError * error = nil;
    PowerAuthCoreConfig * config = [PowerAuthCoreConfig buildWithConfiguration:configuration
                                                           deviceSpecificData:[@"logging-tests" dataUsingEncoding:NSUTF8StringEncoding]
                                                                   instanceId:@"logging-tests"
                                                                    algorithm:PowerAuthCoreAlgorithm_LEGACY_P256
                                                                        error:&error];
    XCTAssertNotNil(config);
    XCTAssertNil(error);
    _session = [PowerAuthCoreSession createWithConfiguration:config error:&error];
    XCTAssertNotNil(_session);
    XCTAssertNil(error);
    [_collector clear];
}

- (void) tearDown
{
    PowerAuthLogSetDelegate(nil);
    _session = nil;
    PowerAuthLogSetEnabled(_savedEnabled);
    PowerAuthLogSetVerbose(_savedVerbose);
    PowerAuthLogToConsoleSetEnabled(_savedConsole);
    _collector = nil;
    [super tearDown];
}

- (void) testLoggingDefaults
{
    XCTAssertTrue(_savedEnabled);
    XCTAssertTrue(_savedVerbose);
    XCTAssertTrue(_savedConsole);
    XCTAssertTrue(PowerAuthCoreLogIsEnabled());
}

- (void) testAllLayersReachDelegateWithoutConsole
{
    PowerAuthLog(@"SDK %@", @"message");
    PowerAuthCoreLog(@"core %d", 42);
    [_session.timeSynchronizationService resetTimeSynchronization];

    NSArray * expected = @[@"SDK message", @"[PowerAuthCore] core 42", NativeTimeLog];
    XCTAssertEqualObjects(_collector.messages, expected);
    XCTAssertFalse(PowerAuthLogToConsoleIsEnabled());
}

- (void) testLongCoreMessagesAreNotTruncated
{
    NSString * body = [@"" stringByPaddingToLength:8192 withString:@"x" startingAtIndex:0];
    body = [body stringByAppendingString:@"-\u017E-end"];
    PowerAuthCoreLog(@"payload=%@ count=%d", body, 17);

    NSString * expected = [NSString stringWithFormat:@"[PowerAuthCore] payload=%@ count=17", body];
    XCTAssertEqualObjects(_collector.messages, @[expected]);
}

- (void) testLoggingCanStillBeDisabled
{
    PowerAuthLogSetEnabled(NO);
    PowerAuthLog(@"disabled SDK");
    PowerAuthCoreLog(@"disabled core");
    [_session.timeSynchronizationService resetTimeSynchronization];

    XCTAssertFalse(PowerAuthCoreLogIsEnabled());
    XCTAssertEqual(_collector.messages.count, 0u);

    PowerAuthLogSetEnabled(YES);
    [_session.timeSynchronizationService resetTimeSynchronization];
    XCTAssertEqualObjects(_collector.messages, @[NativeTimeLog]);
}

- (void) testCriticalWarningsReachDelegateWhenDisabled
{
    PowerAuthLogSetEnabled(NO);
    PowerAuthCriticalWarning(@"critical %d", 42);
    XCTAssertEqualObjects(_collector.messages, @[@"CRITICAL WARNING: critical 42"]);
    XCTAssertFalse(PowerAuthLogIsEnabled());
    XCTAssertFalse(PowerAuthLogToConsoleIsEnabled());
}

- (void) testDelegateReplacementAndRemoval
{
    [_session.timeSynchronizationService resetTimeSynchronization];
    PA2LogCollector * replacement = [[PA2LogCollector alloc] init];
    PowerAuthLogSetDelegate(replacement);
    PowerAuthCoreLog(@"second");
    PowerAuthLogSetDelegate(nil);
    [_session.timeSynchronizationService resetTimeSynchronization];
    PowerAuthLog(@"not captured");

    XCTAssertEqualObjects(_collector.messages, @[NativeTimeLog]);
    XCTAssertEqualObjects(replacement.messages, @[@"[PowerAuthCore] second"]);
}

- (void) testDelegateCanReconfigureLogging
{
    _collector.onLog = ^(NSString * message) {
        PowerAuthLogToConsoleSetEnabled(NO);
        PowerAuthLogSetDelegate(nil);
    };
    [_session.timeSynchronizationService resetTimeSynchronization];
    PowerAuthCoreLog(@"not captured");

    XCTAssertEqualObjects(_collector.messages, @[NativeTimeLog]);
}

- (void) testConcurrentNativeMessages
{
    dispatch_apply(128, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t index) {
        PowerAuthCoreLog(@"concurrent %zu", index);
        [_session.timeSynchronizationService resetTimeSynchronization];
    });
    NSArray<NSString*> * messages = _collector.messages;
    XCTAssertEqual(messages.count, 256u);
    for (NSUInteger index = 0; index < 128; ++index) {
        NSString * expected = [NSString stringWithFormat:@"[PowerAuthCore] concurrent %lu", (unsigned long)index];
        XCTAssertTrue([messages containsObject:expected]);
    }
    NSPredicate * nativeMessages = [NSPredicate predicateWithFormat:@"SELF == %@", NativeTimeLog];
    XCTAssertEqual([messages filteredArrayUsingPredicate:nativeMessages].count, 128u);
}

@end
