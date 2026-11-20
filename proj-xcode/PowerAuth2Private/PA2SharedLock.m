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
#import "PowerAuthLog.h"
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
     Path to the file used for locking.
     */
    char * path;
    /**
     File descriptor. If -1, then the lock is not acquired.
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

- (instancetype) initWithPath:(NSString*)path
                    recursive:(BOOL)recursive
                        error:(NSError**)error
{
    self = [super init];
    if (self) {
        if (!_LockInit(path, recursive, &_lockData)) {
            PA2SetError(error, PowerAuthErrorCode_Other, @"Failed to initialize shared lock");
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

- (id<NSLocking>) createLocalRecursiveLock
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
    lockData->path = strdup(lockPath.UTF8String);
        
    if (recursive) {
        lockData->lockFunc      = _LockRecursive;
        lockData->tryLockFunc   = _TryLockRecursive;
        lockData->unlockFunc    = _UnlockRecursive;
        lockData->closeFunc     = _CloseRecursive;
    } else {
        lockData->lockFunc      = _LockAcquire;
        lockData->tryLockFunc   = _LockAcquire;
        lockData->unlockFunc    = _LockRelease;
        lockData->closeFunc     = _CloseSimple;
    }
    
    BOOL result = NO;
    do {
        // Test whether the file for locking can be opened.
        int fileDescriptor = _LockFileOpen(lockData);
        if (fileDescriptor == -1) {
            break;
        }
        close(fileDescriptor);
        // The file is opened for each lock acquisition, so it must be accessible also when the device is locked.
        NSError * error = nil;
        if (![[NSFileManager defaultManager] setAttributes:@{ NSFileProtectionKey : NSFileProtectionCompleteUntilFirstUserAuthentication }
                                              ofItemAtPath:lockPath
                                                     error:&error]) {
            PowerAuthLog(@"PA2SharedLock: Failed to change protection of lock file: %@", error);
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
 Open the file used for locking. The file is opened only while the lock is being acquired or held.
 iOS terminates the suspended process that has an open file locked in the app group container,
 even if the lock is held by another process (0xdead10cc).
 */
static int _LockFileOpen(LockData * ld)
{
    int fileDescriptor = open(ld->path, O_CREAT | O_RDWR, 0666);
    if (fileDescriptor == -1) {
        int error = errno;
        PA2PrintErrno(@"PA2SharedLock: open()");
        errno = error;
    }
    return fileDescriptor;
}

/**
 Acquire file lock. The operation parameter must be:
 - `LOCK_SH` to acquire read lock.
 - `LOCK_EX` to acquire write lock.
 - `LOCK_NB` can be combined with `LOCK_SH` and `LOCK_EX`
 
 If the lock is held by somebody else and `LOCK_NB` is used, then returns NO and errno is `EWOULDBLOCK`.
 */
static BOOL _LockAcquire(LockData * ld, int operation)
{
    if (ld->fileDescriptor != -1) {
        // The lock is already acquired.
        return YES;
    }
    int fileDescriptor = _LockFileOpen(ld);
    if (fileDescriptor == -1) {
        return NO;
    }
    if (flock(fileDescriptor, operation) != 0) {
        int error = errno;
        if (!((operation & LOCK_NB) && (error == EWOULDBLOCK))) {
            PA2PrintErrno([NSString stringWithFormat:@"PA2SharedLock: flock(_, %d)", operation]);
        }
        close(fileDescriptor);
        errno = error;
        return NO;
    }
    ld->fileDescriptor = fileDescriptor;
    return YES;
}

/**
 Release previously acquired file lock. The lock is released by closing the file.
 */
static BOOL _LockRelease(LockData * ld, int operation)
{
    if (ld->fileDescriptor != -1) {
        close(ld->fileDescriptor);
        ld->fileDescriptor = -1;
    }
    return YES;
}

#pragma mark - Simple lock

static void _CloseSimple(LockData * ld)
{
    // Release the lock if it's still acquired.
    _LockRelease(ld, LOCK_UN);
    free(ld->path);
    ld->path = NULL;
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
        return _LockAcquire(ld, operation);
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
    if (ld->lockCount == 1 && !_LockAcquire(ld, operation)) {
        ld->lockCount--;
        pthread_mutex_unlock(&ld->mutex);
        return NO;
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
                _LockRelease(ld, operation);
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
    // Release also the file lock
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


#pragma mark - Suspendable lock

/// Interval between attempts to acquire the lock held by another process.
static const useconds_t kLockRetryInterval = 20 * 1000;
/// How long to wait until the system starts, or refuses to start the expiring activity.
static const int64_t kActivityStartTimeout = 1 * NSEC_PER_SEC;

/**
 The `PA2ExpiringActivity` keeps the process running until the activity is ended,
 or until the system decides to suspend the process anyway.
 */
@interface PA2ExpiringActivity : NSObject

/// Contains YES if the system is about to suspend the process.
@property (atomic) BOOL expired;

/**
 Begin the activity. Returns nil if the system refused to keep the process running.
 The expiration handler is called when the process is about to be suspended.
 */
+ (instancetype) beginWithExpirationHandler:(void(^)(PA2ExpiringActivity * activity))handler;
/// End the activity.
- (void) end;

@end

@implementation PA2ExpiringActivity
{
    dispatch_semaphore_t _started;
    dispatch_semaphore_t _ended;
}

- (instancetype) init
{
    self = [super init];
    if (self) {
        _started = dispatch_semaphore_create(0);
        _ended = dispatch_semaphore_create(0);
    }
    return self;
}

+ (instancetype) beginWithExpirationHandler:(void (^)(PA2ExpiringActivity *))handler
{
    PA2ExpiringActivity * activity = [[PA2ExpiringActivity alloc] init];
    [[NSProcessInfo processInfo] performExpiringActivityWithReason:@"PA2SharedLock" usingBlock:^(BOOL expired) {
        if (expired) {
            // The system refused to start the activity, or the time is up.
            activity.expired = YES;
            handler(activity);
            [activity end];
        }
        dispatch_semaphore_signal(activity->_started);
        if (!expired) {
            // The process is not suspended until this block returns.
            dispatch_semaphore_wait(activity->_ended, DISPATCH_TIME_FOREVER);
        }
    }];
    // If the system didn't respond in time, then the activity is treated as started. If it's refused later,
    // then the expiration handler is called.
    dispatch_semaphore_wait(activity->_started, dispatch_time(DISPATCH_TIME_NOW, kActivityStartTimeout));
    return activity.expired ? nil : activity;
}

- (void) end
{
    dispatch_semaphore_signal(_ended);
}

@end


@implementation PA2SuspendableSharedLock
{
    /// Guards `_activity` together with the state of the file lock.
    NSLock * _stateLock;
    /// Activity that keeps the process running. Not nil while the lock is held.
    PA2ExpiringActivity * _activity;
}

- (instancetype) initWithPath:(NSString *)path error:(NSError **)error
{
    self = [super initWithPath:path recursive:NO error:error];
    if (self) {
        _stateLock = [[NSLock alloc] init];
    }
    return self;
}

- (void) dealloc
{
    [self unlock];
}

- (void) lock
{
    [self acquireAndWait:YES];
}

- (BOOL) tryLock
{
    return [self acquireAndWait:NO];
}

- (void) unlock
{
    [_stateLock lock];
    PA2ExpiringActivity * activity = _activity;
    _activity = nil;
    [super unlock];
    [_stateLock unlock];
    [activity end];
}

/**
 Acquire the lock and keep it until the process is about to be suspended. If wait is YES,
 then waits for the lock held by another process. Returns NO if the lock is not available.
 */
- (BOOL) acquireAndWait:(BOOL)wait
{
    [_stateLock lock];
    BOOL held = _activity != nil;
    [_stateLock unlock];
    if (held) {
        return YES;
    }
    __weak PA2SuspendableSharedLock * weakSelf = self;
    PA2ExpiringActivity * activity = [PA2ExpiringActivity beginWithExpirationHandler:^(PA2ExpiringActivity * expiredActivity) {
        [weakSelf releaseLockKeptByActivity:expiredActivity];
    }];
    BOOL available = NO;
    for (BOOL waiting = NO; ; waiting = YES) {
        BOOL busy = NO;
        [_stateLock lock];
        // The waiting thread must not touch the lock file once the activity expired,
        // because the process can be suspended at any time.
        if (!(waiting && activity.expired)) {
            available = [super tryLock];
            // Wait only for the lock held by another process.
            busy = !available && errno == EWOULDBLOCK;
            if (available && !_activity) {
                if (activity && !activity.expired) {
                    _activity = activity;
                    activity = nil;
                } else {
                    // The process can be suspended at any time, so the lock cannot be kept.
                    [super unlock];
                }
            }
        }
        [_stateLock unlock];
        if (!busy || !wait || !activity || activity.expired) {
            break;
        }
        usleep(kLockRetryInterval);
    }
    [activity end];
    return available;
}

/**
 Release the lock, because the process is about to be suspended.
 */
- (void) releaseLockKeptByActivity:(PA2ExpiringActivity*)activity
{
    [_stateLock lock];
    BOOL released = _activity == activity;
    if (released) {
        _activity = nil;
        [super unlock];
    }
    [_stateLock unlock];
    if (released) {
        PowerAuthLog(@"PA2SharedLock: Lock released due to process suspension.");
    }
}

@end
