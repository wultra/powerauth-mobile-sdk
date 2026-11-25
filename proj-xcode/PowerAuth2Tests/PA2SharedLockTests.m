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
#import <UIKit/UIApplication.h>
#import <sys/param.h>
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
}

- (void) tearDown
{
    [[NSFileManager defaultManager] removeItemAtPath:_path error:nil];
}

/// Simulates the application that entered the background.
- (void) enterBackground
{
    [[NSNotificationCenter defaultCenter] postNotificationName:UIApplicationDidEnterBackgroundNotification object:nil];
}

/// Simulates the application that returned to the foreground.
- (void) enterForeground
{
    [[NSNotificationCenter defaultCenter] postNotificationName:UIApplicationDidBecomeActiveNotification object:nil];
}

- (PA2SharedLock*) lock:(BOOL)recursive
{
    PA2SharedLock * lock = [[PA2SharedLock alloc] initWithPath:_path recursive:recursive error:nil];
    XCTAssertNotNil(lock);
    return lock;
}

/// Returns the lock of the application that is in the foreground. The tests run without the application
/// object, so the new lock treats the application as a background one until it's told otherwise.
- (PA2ForegroundSharedLock*) foregroundLock
{
    PA2ForegroundSharedLock * lock = [[PA2ForegroundSharedLock alloc] initWithPath:_path error:nil];
    XCTAssertNotNil(lock);
    [self enterForeground];
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
- (dispatch_semaphore_t) lockInBackgroundThread:(PA2SharedLock*)lock
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

#pragma mark - Lock file

- (void) testExclusiveAccess
{
    for (NSArray<PA2SharedLock*> * locks in @[ @[ [self lock:NO], [self lock:NO] ],
                                               @[ [self foregroundLock], [self foregroundLock] ] ]) {
        PA2SharedLock * lock1 = locks[0], * lock2 = locks[1];
        XCTAssertTrue([lock1 tryLock]);
        XCTAssertFalse([lock2 tryLock]);
        [lock1 unlock];
        XCTAssertTrue([lock2 tryLock]);
        XCTAssertFalse([lock1 tryLock]);
        [lock2 unlock];
    }
    // The recursive lock excludes the foreground one, too.
    PA2SharedLock * recursiveLock = [self lock:YES];
    PA2ForegroundSharedLock * foregroundLock = [self foregroundLock];
    [recursiveLock lock];
    XCTAssertFalse([foregroundLock tryLock]);
    [recursiveLock unlock];
    XCTAssertTrue([foregroundLock tryLock]);
    [foregroundLock unlock];
}

- (void) testLockFileIsOpenedOnlyWhileLockIsAcquired
{
    PA2SharedLock * holder = [self lock:NO];
    for (PA2SharedLock * lock in @[ [self lock:NO], [self lock:YES], [self foregroundLock] ]) {
        XCTAssertFalse([self isLockFileOpened]);
        XCTAssertTrue([lock tryLock]);
        XCTAssertTrue([self isLockFileOpened]);
        [lock unlock];
        XCTAssertFalse([self isLockFileOpened]);
    }
    // Failed attempt must not keep the file opened.
    PA2SharedLock * lock = [self lock:NO];
    XCTAssertTrue([holder tryLock]);
    XCTAssertFalse([lock tryLock]);
    [holder unlock];
    XCTAssertFalse([self isLockFileOpened]);
}

#pragma mark - Foreground lock

- (void) testForegroundLockIsReleasedInBackground
{
    PA2ForegroundSharedLock * lock = [self foregroundLock];
    PA2SharedLock * other = [self lock:NO];
    XCTAssertTrue([lock tryLock]);
    XCTAssertTrue(lock.isLocked);
    XCTAssertFalse([other tryLock]);

    [self enterBackground];
    XCTAssertFalse(lock.isLocked);
    XCTAssertFalse([self isLockFileOpened]);
    XCTAssertTrue([other tryLock]);
    [other unlock];

    // The lock is acquired again once the application is back, and the next unlock releases it.
    [self enterForeground];
    XCTAssertFalse([self isLockFileOpened]);
    XCTAssertTrue([lock tryLock]);
    XCTAssertFalse([other tryLock]);
    [lock unlock];
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testForegroundLockIsNotKeptInBackground
{
    PA2ForegroundSharedLock * lock = [self foregroundLock];
    PA2SharedLock * other = [self lock:NO];
    [self enterBackground];

    // The lock is available, but it's not kept.
    XCTAssertTrue([lock tryLock]);
    XCTAssertFalse(lock.isLocked);
    XCTAssertFalse([self isLockFileOpened]);
    // The lock held by somebody else is still reported, and nobody waits for it.
    XCTAssertTrue([other tryLock]);
    XCTAssertFalse([lock tryLock]);
    XCTAssertTrue(_Wait([self lockInBackgroundThread:lock], 5));
    XCTAssertFalse(lock.isLocked);
    [other unlock];
}

- (void) testForegroundLockIsReleasedWhenDestroyed
{
    @autoreleasepool {
        PA2ForegroundSharedLock * lock = [self foregroundLock];
        XCTAssertTrue([lock tryLock]);
        XCTAssertTrue([self isLockFileOpened]);
        lock = nil;
    }
    XCTAssertFalse([self isLockFileOpened]);
}

- (void) testForegroundLockWaitsForRelease
{
    PA2ForegroundSharedLock * lock1 = [self foregroundLock];
    PA2ForegroundSharedLock * lock2 = [self foregroundLock];
    XCTAssertTrue([lock1 tryLock]);
    dispatch_semaphore_t returned = [self lockInBackgroundThread:lock2];
    XCTAssertFalse(_Wait(returned, 0.2));
    [lock1 unlock];
    XCTAssertTrue(_Wait(returned, 5));
    XCTAssertTrue(lock2.isLocked);
    [lock2 unlock];
}

- (void) testForegroundLockStopsWaitingInBackground
{
    PA2SharedLock * holder = [self lock:NO];
    PA2ForegroundSharedLock * lock = [self foregroundLock];
    XCTAssertTrue([holder tryLock]);
    dispatch_semaphore_t returned = [self lockInBackgroundThread:lock];
    XCTAssertFalse(_Wait(returned, 0.2));
    [self enterBackground];
    XCTAssertTrue(_Wait(returned, 5));
    XCTAssertFalse(lock.isLocked);
    [holder unlock];
}

- (void) testForegroundLockIsNeverKeptAfterBackgroundNotification
{
    // Threads acquire and release the lock all the time while the application enters the background.
    // The thread stops right after the acquisition, so the lock stays locked if it's kept after
    // the notification.
    PA2ForegroundSharedLock * lock = [self foregroundLock];
    for (int round = 0; round < 100; round++) {
        [self enterForeground];
        __block volatile BOOL stop = NO;
        dispatch_group_t group = dispatch_group_create();
        for (int thread = 0; thread < 2; thread++) {
            dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                while (YES) {
                    [lock tryLock];
                    if (stop) {
                        break;
                    }
                    [lock unlock];
                    // Let the main thread get to the lock's state.
                    usleep(20);
                }
            });
        }
        usleep(arc4random_uniform(2000));
        [self enterBackground];
        stop = YES;
        dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
        if (lock.isLocked || [self isLockFileOpened]) {
            XCTFail(@"The lock is kept in the background, round %d", round);
            break;
        }
    }
}

@end
