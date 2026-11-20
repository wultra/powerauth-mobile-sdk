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

#import "ProcessSuspensionHelper.h"
#import <objc/runtime.h>

/// Blocks of expiring activities that keep the process running.
static NSMutableArray<void(^)(BOOL)> * s_activities;
static BOOL s_processSuspendable;
static BOOL s_activityStartDelayed;

@interface NSProcessInfo (ProcessSuspensionHelper)
@end

@implementation NSProcessInfo (ProcessSuspensionHelper)

- (void) pa2test_performExpiringActivityWithReason:(NSString *)reason usingBlock:(void (^)(BOOL))block
{
    BOOL refused, delayed;
    @synchronized ([ProcessSuspensionHelper class]) {
        refused = s_processSuspendable;
        delayed = s_activityStartDelayed;
        if (!refused) {
            [s_activities addObject:block];
        }
    }
    if (!delayed) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            block(refused);
        });
    }
}

@end

@implementation ProcessSuspensionHelper

+ (void) exchangeExpiringActivityImplementation
{
    // The shared instance can be a private subclass with its own implementation.
    Class processInfoClass = object_getClass([NSProcessInfo processInfo]);
    Method original = class_getInstanceMethod(processInfoClass, @selector(performExpiringActivityWithReason:usingBlock:));
    Method replacement = class_getInstanceMethod(processInfoClass, @selector(pa2test_performExpiringActivityWithReason:usingBlock:));
    method_exchangeImplementations(original, replacement);
}

+ (void) startSimulation
{
    @synchronized (self) {
        if (s_activities) {
            return;
        }
        s_activities = [NSMutableArray array];
        s_processSuspendable = NO;
        s_activityStartDelayed = NO;
    }
    [self exchangeExpiringActivityImplementation];
}

+ (void) stopSimulation
{
    @synchronized (self) {
        if (!s_activities) {
            return;
        }
    }
    [self exchangeExpiringActivityImplementation];
    [self suspendProcess];
    @synchronized (self) {
        s_activities = nil;
    }
}

+ (BOOL) waitForActivities:(NSUInteger)count
{
    for (int attempt = 0; attempt < 500; attempt++) {
        @synchronized (self) {
            if (s_activities.count == count) {
                return YES;
            }
        }
        usleep(10 * 1000);
    }
    return NO;
}

+ (void) suspendProcess
{
    NSArray<void(^)(BOOL)> * activities;
    @synchronized (self) {
        activities = [s_activities copy];
        [s_activities removeAllObjects];
    }
    for (void(^block)(BOOL) in activities) {
        block(YES);
    }
}

+ (void) setProcessSuspendable:(BOOL)suspendable
{
    @synchronized (self) {
        s_processSuspendable = suspendable;
    }
}

+ (void) setActivityStartDelayed:(BOOL)delayed
{
    @synchronized (self) {
        s_activityStartDelayed = delayed;
    }
}

@end
