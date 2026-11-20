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

#import <Foundation/Foundation.h>

/**
 The `ProcessSuspensionHelper` takes control over the expiring activities started
 in this process, so the test can simulate the moment when the system is about
 to suspend the process.
 */
@interface ProcessSuspensionHelper : NSObject

/// Take control over expiring activities started in this process.
+ (void) startSimulation;
/// Return control over expiring activities back to the system.
+ (void) stopSimulation;
/// Wait until the given number of expiring activities is started since the last `suspendProcess` call.
+ (BOOL) waitForActivities:(NSUInteger)count;
/// Simulate the moment when the system is about to suspend the process.
+ (void) suspendProcess;
/// If YES, then simulate the process that can be suspended at any time,
/// so the system refuses to start a new expiring activity.
+ (void) setProcessSuspendable:(BOOL)suspendable;
/// If YES, then the system doesn't respond to the request to start a new expiring activity,
/// until `suspendProcess` is called.
+ (void) setActivityStartDelayed:(BOOL)delayed;

@end
