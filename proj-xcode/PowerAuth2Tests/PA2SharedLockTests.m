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
#import <sys/param.h>
#import <PowerAuth2TestsBase/ProcessSuspensionHelper.h>
#import "PA2SharedLock.h"

@interface PA2SharedLockTests : XCTestCase
@end

@implementation PA2SharedLockTests
{
    NSString * _path;
}

- (void) setUp
{
    _path = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID].UUIDString stringByAppendingString:@".lock"]];
    [ProcessSuspensionHelper startSimulation];
}

- (void) tearDown
{
    [ProcessSuspensionHelper stopSimulation];
    [[NSFileManager defaultManager] removeItemAtPath:_path error:nil];
}

- (PA2SharedLock*) lock:(BOOL)recursive
{
    PA2SharedLock * lock = [[PA2SharedLock alloc] initWithPath:_path recursive:recursive error:nil];
    XCTAssertNotNil(lock);
    return lock;
}

- (PA2SuspendableSharedLock*) suspendableLock
{
    PA2SuspendableSharedLock * lock = [[PA2SuspendableSharedLock alloc] initWithPath:_path error:nil];
    XCTAssertNotNil(lock);
    return lock;
}

/// Returns YES if this process has an open descriptor of the lock file.
- (BOOL) isLockFileOpened
{
    char lockPath[MAXPATHLEN], path[MAXPATHLEN];
    if (!realpath(_path.fileSystemRepresentation, lockPath)) {
        XCTFail(@"Lock file doesn't exist");
        return NO;
    }
    for (int fd = 0; fd < getdtablesize(); fd++) {
        if (fcntl(fd, F_GETPATH, path) == 0 && !strcmp(path, lockPath)) {
            return YES;
        }
    }
    return NO;
}

/// Calls `lock` in a background thread and returns semaphore signalled after the method returns.
- (dispatch_semaphore_t) lockInBackground:(PA2SharedLock*)lock
{
    dispatch_semaphore_t returned = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        [lock lock];
        dispatch_semaphore_signal(returned);
    });
    return returned;
}

static BOOL _Wait(dispatch_semaphore_t semaphore, NSTimeInterval seconds)
{
    return dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC))) == 0;
}

- (void) testInitWithWrongPath
{
    NSError * error = nil;
    NSString * path = [_path stringByAppendingPathComponent:@"missing/file.lock"];
    XCTAssertNil([[PA2SharedLock alloc] initWithPath:path recursive:NO error:&error]);
    XCTAssertNotNil(error);
    error = nil;
    XCTAssertNil([[PA2SuspendableSharedLock alloc] initWithPath:path error:&error]);
    XCTAssertNotNil(error);
}

- (void) testExclusiveAccess
{
    for (NSArray<PA2SharedLock*> * locks in @[ @[ [self lock:NO], [self lock:NO] ],
                                               @[ [self suspendableLock], [self suspendableLock] ],
                                               @[ [self lock:YES], [self suspendableLock] ] ]) {
        PA2SharedLock * lock1 = locks[0], * lock2 = locks[1];
        XCTAssertTrue([lock1 tryLock]);
        XCTAssertFalse([lock2 tryLock]);
        [lock1 unlock];
        XCTAssertTrue([lock2 tryLock]);
        XCTAssertFalse([lock1 tryLock]);
        [lock2 unlock];
    }
}

- (void) testRecursiveLock
{
    PA2SharedLock * lock1 = [self lock:YES];
    PA2SharedLock * lock2 = [self lock:NO];
    [lock1 lock];
    XCTAssertTrue([lock1 tryLock]);
    XCTAssertFalse([lock2 tryLock]);
    [lock1 unlock];
    XCTAssertFalse([lock2 tryLock]);
    [lock1 unlock];
    XCTAssertTrue([lock2 tryLock]);
    [lock2 unlock];
}

- (void) testLockFileIsOpenedOnlyWhileLockIsHeld
{
    PA2SharedLock * holder = [self lock:NO];
    for (PA2SharedLock * lock in @[ [self lock:NO], [self lock:YES], [self suspendableLock] ]) {
        XCTAssertFalse([self isLockFileOpened]);
        XCTAssertTrue([lock tryLock]);
        XCTAssertTrue([self isLockFileOpened]);
        [lock unlock];
        XCTAssertFalse([self isLockFileOpened]);
        // Failed attempt must not keep the file opened.
        XCTAssertTrue([holder tryLock]);
        XCTAssertFalse([lock tryLock]);
        [holder unlock];
        XCTAssertFalse([self isLockFileOpened]);
    }
}

- (void) testSuspendableLockIsReleasedBeforeSuspension
{
    PA2SuspendableSharedLock * lock1 = [self suspendableLock];
    PA2SuspendableSharedLock * lock2 = [self suspendableLock];
    XCTAssertTrue([lock1 tryLock]);
    XCTAssertFalse([lock2 tryLock]);

    [ProcessSuspensionHelper suspendProcess];
    XCTAssertFalse([self isLockFileOpened]);
    XCTAssertTrue([lock2 tryLock]);
    XCTAssertFalse([lock1 tryLock]);
    [lock2 unlock];

    // The lock can be acquired again and the unlock after the expiration is harmless.
    XCTAssertTrue([lock1 tryLock]);
    XCTAssertTrue([lock1 tryLock]);
    XCTAssertFalse([lock2 tryLock]);
    [lock1 unlock];
    [lock1 unlock];
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testSuspendableLockIsNotKeptWhenProcessCanBeSuspended
{
    PA2SuspendableSharedLock * lock = [self suspendableLock];
    PA2SharedLock * holder = [self lock:NO];
    [ProcessSuspensionHelper setProcessSuspendable:YES];

    // The lock is available, but it's not kept.
    XCTAssertTrue([lock tryLock]);
    XCTAssertFalse([self isLockFileOpened]);
    XCTAssertTrue([holder tryLock]);
    // The lock held by somebody else is still reported, and nobody waits for it.
    XCTAssertFalse([lock tryLock]);
    XCTAssertTrue(_Wait([self lockInBackground:lock], 5));
    [holder unlock];
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testSuspendableLockDoesNotWaitForUnavailableLockFile
{
    PA2SuspendableSharedLock * lock = [self suspendableLock];
    PA2SharedLock * recursiveLock = [self lock:YES];
    // The lock file cannot be opened if there's a directory at its path.
    [[NSFileManager defaultManager] removeItemAtPath:_path error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:_path withIntermediateDirectories:NO attributes:nil error:nil];
    XCTAssertFalse([lock tryLock]);
    XCTAssertTrue(_Wait([self lockInBackground:lock], 5));
    XCTAssertFalse([recursiveLock tryLock]);
    // The failed attempt must not affect the next one.
    [[NSFileManager defaultManager] removeItemAtPath:_path error:nil];
    XCTAssertTrue([recursiveLock tryLock]);
    XCTAssertTrue([self isLockFileOpened]);
    [recursiveLock unlock];
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testSuspendableLockIsKeptWhenActivityStartIsDelayed
{
    PA2SuspendableSharedLock * lock = [self suspendableLock];
    [ProcessSuspensionHelper setActivityStartDelayed:YES];
    // The system didn't respond in time, but that's not a refusal.
    XCTAssertTrue([lock tryLock]);
    XCTAssertTrue([self isLockFileOpened]);
    // The activity is refused later.
    [ProcessSuspensionHelper suspendProcess];
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testSuspendableLockIsReleasedWhenDestroyed
{
    @autoreleasepool {
        XCTAssertTrue([[self suspendableLock] tryLock]);
        XCTAssertTrue([self isLockFileOpened]);
    }
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testSuspendableLockWaitsForRelease
{
    PA2SuspendableSharedLock * lock1 = [self suspendableLock];
    PA2SuspendableSharedLock * lock2 = [self suspendableLock];
    XCTAssertTrue([lock1 tryLock]);
    dispatch_semaphore_t returned = [self lockInBackground:lock2];
    XCTAssertFalse(_Wait(returned, 0.2));
    [lock1 unlock];
    XCTAssertTrue(_Wait(returned, 5));
    XCTAssertFalse([lock1 tryLock]);
    [lock2 unlock];
}

- (void) testSuspendableLockStopsWaitingBeforeSuspension
{
    PA2SharedLock * holder = [self lock:NO];
    PA2SuspendableSharedLock * lock = [self suspendableLock];
    XCTAssertTrue([holder tryLock]);
    dispatch_semaphore_t returned = [self lockInBackground:lock];
    XCTAssertTrue([ProcessSuspensionHelper waitForActivities:1]);
    XCTAssertFalse(_Wait(returned, 0.2));
    [ProcessSuspensionHelper suspendProcess];
    XCTAssertTrue(_Wait(returned, 5));
    [holder unlock];
    // The lock was not acquired by the waiting thread.
    XCTAssertFalse([self isLockFileOpened]);
    XCTAssertTrue([holder tryLock]);
    [holder unlock];
}

@end
