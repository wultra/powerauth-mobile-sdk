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

#import "PA2SharedLock.h"
#import "PA2PrivateMacros.h"
#import <PowerAuth2/PowerAuthLog.h>
#include <pthread.h>

#pragma mark - Internal objects

@interface PA2InternalLock : NSObject<NSLocking>
- (id) initWithSharedLock:(PA2SharedLock*)sharedLock;
@end

/**
 Internal structure containing lock data.
 */
typedef struct LockData {
    /**
     Pointer to function that implements lock function.
     */
    BOOL (*lockFunc)(struct LockData * data, int operation);
    /**
     Pointer to function that implements tryLock function.
     */
    BOOL (*tryLockFunc)(struct LockData * data, int operation);
    /**
     Pointer to function that implements unlock function.
     */
    BOOL (*unlockFunc)(struct LockData * data, int operation);
    /**
     Pointer to function that implements close lock function.
     */
    void (*closeFunc)(struct LockData * data);
    /**
     File descriptor. If -1, then no file is opened.
     */
    int fileDescriptor;
    
    /**
     Flag indicates that mutex property is initialized and needs to be destroyed.
     */
    BOOL mutexInitialized;
    /**
     mutex implementation, valid only if recursive mode is turned on.
     */
    pthread_mutex_t mutex;
    /**
     How many times the lock has been acquired from the current thread.
     */
    int lockCount;
    
} LockData;

@implementation PA2SharedLock
{
    LockData _lockData;
    BOOL _recursive;
}

static BOOL _LockInit(NSString * lockPath, BOOL recursive, LockData * lockData);

#pragma mark - Public interface

- (instancetype) initWithPath:(NSString *)path recursive:(BOOL)recursive
{
    self = [super init];
    if (self) {
        if (_LockInit(path, recursive, &_lockData) == NO) {
            PowerAuthLog(@"PA2SharedLock: Failed to initialize %@ lock", recursive ? @"recursive" : @"simple");
            return nil;
        }
        _recursive = recursive;
    }
    return self;
}

- (void) dealloc
{
    _lockData.closeFunc(&_lockData);
}

- (void) lock
{
    _lockData.lockFunc(&_lockData, LOCK_EX);
}

- (void) unlock
{
    _lockData.unlockFunc(&_lockData, LOCK_UN);
}

- (BOOL) tryLock
{
    return _lockData.tryLockFunc(&_lockData, LOCK_EX | LOCK_NB);
}

- (void) localLock
{
    _LockRecursive(&_lockData, 0);
}

- (void) localUnlock
{
    _UnlockRecursive(&_lockData, 0);
}

- (id<NSLocking>) createLocalRecusiveLock
{
    return _recursive ? [[PA2InternalLock alloc] initWithSharedLock:self] : nil;
}

#pragma mark - Private

/**
 Initialize LockData structure for given file and lock type.
 Returns NO if initialization failed.
 */
static BOOL _LockInit(NSString * lockPath, BOOL recursive, LockData * lockData)
{
    memset(lockData, 0, sizeof(LockData));
    lockData->fileDescriptor = -1;
        
    if (recursive) {
        lockData->lockFunc      = _LockRecursive;
        lockData->tryLockFunc   = _TryLockRecursive;
        lockData->unlockFunc    = _UnlockRecursive;
        lockData->closeFunc     = _CloseRecursive;
    } else {
        lockData->lockFunc      = _LockOperation;
        lockData->tryLockFunc   = _LockOperation;
        lockData->unlockFunc    = _LockOperation;
        lockData->closeFunc     = _CloseSimple;
    }
    
    BOOL result = NO;
    do {
        // Open file for locking
        lockData->fileDescriptor = open(lockPath.UTF8String, O_CREAT | O_TRUNC | O_RDWR, 0666);
        if (lockData->fileDescriptor == -1) {
            PA2PrintErrno(@"PA2SharedLock: open()");
            break;
        }
        // If lock is recursive, then also initialize pthread mutex.
        if (recursive) {
            pthread_mutexattr_t attr;
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            int int_result = pthread_mutex_init(&lockData->mutex, &attr);
            pthread_mutexattr_destroy(&attr);
            if (int_result != 0) {
                PA2PrintErrno(@"PA2SharedLock: pthread_mutex_init()");
                break;
            }
            lockData->mutexInitialized = YES;
        }
        
        // Everything looks OK
        result = YES;

    } while (false);
    
    if (result == NO) {
        // Cleanup failed initialized lock
        lockData->closeFunc(lockData);
    }
    return result;
}

/**
 Acquire or release file lock. The operation parameter must be:
 - `LOCK_SH` to acquire read lock.
 - `LOCK_EX` to acquire write lock.
 - `LOCK_UN` to release previously acquired lock.
 - `LOCK_NB` can be combined with `LOCK_SH` and `LOCK_EX`
 */
static BOOL _LockOperation(LockData * ld, int operation)
{
    BOOL result;
    if (ld->fileDescriptor != -1) {
        result = flock(ld->fileDescriptor, operation) == 0;
        if (!result && !((operation & LOCK_NB) && (errno == EWOULDBLOCK))) {
            PA2PrintErrno([NSString stringWithFormat:@"PA2SharedLock: flock(_, %d)", operation]);
        }
    } else {
        result = NO;
    }
    return result;
}

#pragma mark - Simple lock

static void _CloseSimple(LockData * ld)
{
    // Close file if we're still have the file descriptor.
    if (ld->fileDescriptor != -1) {
        close(ld->fileDescriptor);
        ld->fileDescriptor = -1;
    }
}

#pragma mark - Recursive lock

static BOOL _LockRecursive(LockData * ld, int operation)
{
    if (!ld->mutexInitialized) {
        return NO;
    }
    // At first, acquire recursive mutex for this thread.
    if (pthread_mutex_lock(&ld->mutex) != 0) {
        PA2PrintErrno(@"PA2SharedLock: pthread_mutex_lock()");
        return NO;
    }
    if (operation == 0) {
        return YES; // lock only pthread_mutex
    }
    
    // Increase number of acquired locks. If count is 1, then we have to acquire
    // exclusive lock on the underlying file.
    ld->lockCount++;
    if (ld->lockCount == 1) {
        return _LockOperation(ld, operation);
    }
    return YES;
}

static BOOL _TryLockRecursive(LockData * ld, int operation)
{
    if (!ld->mutexInitialized) {
        return NO;
    }
    // At first, acquire recursive mutex for this thread.
    if (pthread_mutex_trylock(&ld->mutex) != 0) {
        if (errno != EBUSY) {
            PA2PrintErrno(@"PA2SharedLock: pthread_mutex_lock()");
        }
        return NO;
    }
    if (operation == 0) {
        return YES; // lock only pthread_mutex
    }
    
    // Increase number of acquired locks. If count is 1, then we have to acquire
    // exclusive lock on the underlying file.
    ld->lockCount++;
    if (ld->lockCount == 1) {
        return _LockOperation(ld, operation);
    }
    return YES;
}

static BOOL _UnlockRecursive(LockData * ld, int operation)
{
    if (!ld->mutexInitialized) {
        return NO;
    }
    if (operation != 0) {
        // At first, decrement lock counter.
        if (ld->lockCount > 0) {
            ld->lockCount--;
            // If both counters are equal to 0, then we can also release the underlying file lock.
            if (ld->lockCount == 0) {
                _LockOperation(ld, operation);
            }
        } else {
            PowerAuthLog(@"PA2SharedLock: lock - unlock calls are not in pair.");
        }
    }
    
    // And finally, release recursive pthread mutex.
    if (pthread_mutex_unlock(&ld->mutex) != 0) {
        PA2PrintErrno(@"PA2SharedLock: pthread_mutex_unlock()");
        return NO;
    }
    return YES;
}

static void _CloseRecursive(LockData * ld)
{
    // Destroy mutex if it's still initialized.
    if (ld->mutexInitialized == YES) {
        pthread_mutex_destroy(&ld->mutex);
        ld->mutexInitialized = NO;
    }
    // Close also file descriptor
    _CloseSimple(ld);
}

@end


@implementation PA2InternalLock
{
    PA2SharedLock * _lock;
}

- (id) initWithSharedLock:(PA2SharedLock *)sharedLock
{
    self = [super init];
    if (self) {
        _lock = sharedLock;
    }
    return self;
}

- (void) lock
{
    [_lock localLock];
}

- (void) unlock
{
    [_lock localUnlock];
}

@end
