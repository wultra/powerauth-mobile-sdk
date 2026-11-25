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

- (PA2SharedLock*) lock:(BOOL)recursive
{
    PA2SharedLock * lock = [[PA2SharedLock alloc] initWithPath:_path recursive:recursive error:nil];
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

#pragma mark - Lock file

- (void) testExclusiveAccess
{
    PA2SharedLock * lock1 = [self lock:NO];
    PA2SharedLock * lock2 = [self lock:NO];
    XCTAssertTrue([lock1 tryLock]);
    XCTAssertFalse([lock2 tryLock]);
    [lock1 unlock];
    XCTAssertTrue([lock2 tryLock]);
    XCTAssertFalse([lock1 tryLock]);
    [lock2 unlock];
    // The recursive lock excludes the other locks, too.
    PA2SharedLock * recursiveLock = [self lock:YES];
    [recursiveLock lock];
    XCTAssertFalse([lock1 tryLock]);
    [recursiveLock unlock];
    XCTAssertTrue([lock1 tryLock]);
    [lock1 unlock];
}

- (void) testLockFileIsOpenedOnlyWhileLockIsAcquired
{
    PA2SharedLock * holder = [self lock:NO];
    for (PA2SharedLock * lock in @[ [self lock:NO], [self lock:YES] ]) {
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

@end
