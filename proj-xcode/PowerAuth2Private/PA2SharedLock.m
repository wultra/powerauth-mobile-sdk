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
#import <UIKit/UIApplication.h>

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

- (BOOL) lockWithError:(NSError**)error
{
    if (_lockData.lockFunc(&_lockData, LOCK_EX)) {
        return YES;
    }
    PA2SetError(error, PowerAuthErrorCode_Other, @"Failed to acquire the lock shared between applications");
    return NO;
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

/// The shortest and the longest interval between attempts to acquire the lock held by another process.
/// Unlike a blocking flock(), polling doesn't queue the waiters, but the locks are kept only for short tasks.
static const useconds_t kLockPollIntervalMin = 1000;
static const useconds_t kLockPollIntervalMax = 20 * 1000;

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
        // The file is open only while the lock is acquired, see `_LockOperation()`.
        close(lockData->fileDescriptor);
        lockData->fileDescriptor = -1;
        // The file is opened for each lock acquisition, so it must be accessible also when the device is locked.
        NSFileManager * fileManager = [NSFileManager defaultManager];
        NSFileProtectionType protection = [fileManager attributesOfItemAtPath:lockPath error:nil][NSFileProtectionKey];
        if ([protection isEqualToString:NSFileProtectionComplete] || [protection isEqualToString:NSFileProtectionCompleteUnlessOpen]) {
            NSError * protectionError = nil;
            if (![fileManager setAttributes:@{ NSFileProtectionKey : NSFileProtectionCompleteUntilFirstUserAuthentication } ofItemAtPath:lockPath error:&protectionError]) {
                // Not fatal. The lock cannot be acquired while the device is locked, and the session task fails.
                PowerAuthLog(@"PA2SharedLock: Failed to change protection of the lock file: %@", protectionError);
            }
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
 
 The file is open only while the lock is acquired. iOS terminates a suspended process that has an open
 file locked in the app group container, even if the lock is held by another process (0xdead10cc).
 For the same reason, the lock held by another process is not waited for in `flock()`. The function
 polls with `LOCK_NB` instead, and the file is closed between the attempts. The file is still open for
 the moment of each attempt, which is much shorter than the time the lock is kept by a session task.

 If the lock is not acquired, then `errno` is `EWOULDBLOCK` only if somebody else holds the lock.
 */
static BOOL _LockOperation(LockData * ld, int operation)
{
    if (operation & LOCK_UN) {
        if (ld->fileDescriptor != -1) {
            flock(ld->fileDescriptor, LOCK_UN);
            close(ld->fileDescriptor);
            ld->fileDescriptor = -1;
        }
        return YES;
    }
    useconds_t interval = kLockPollIntervalMin;
    // Nothing to do if the lock is already acquired by this object.
    while (ld->fileDescriptor == -1) {
        int fd = open(ld->path, O_CREAT | O_RDWR, 0666);
        if (fd != -1 && flock(fd, operation | LOCK_NB) == 0) {
            ld->fileDescriptor = fd;
            break;
        }
        int error = errno;
        if (fd != -1) {
            close(fd);
        }
        // Wait only for the lock held by another process.
        BOOL busy = error == EWOULDBLOCK;
        if (!busy) {
            errno = error;
            PA2PrintErrno(@"PA2SharedLock: Failed to lock the file");
        }
        if (!busy || (operation & LOCK_NB)) {
            errno = error;
            return NO;
        }
        usleep(interval);
        interval = MIN(interval * 2, kLockPollIntervalMax);
    }
    return YES;
}

#pragma mark - Simple lock

static void _CloseSimple(LockData * ld)
{
    // Close file if we're still have the file descriptor.
    if (ld->fileDescriptor != -1) {
        close(ld->fileDescriptor);
        ld->fileDescriptor = -1;
    }
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
    
    // If this is the first acquired lock, then we have to acquire exclusive lock
    // on the underlying file. Then increase number of acquired locks.
    if (ld->lockCount == 0 && !_LockOperation(ld, operation)) {
        // The file is not locked, so the mutex is not kept either.
        pthread_mutex_unlock(&ld->mutex);
        return NO;
    }
    ld->lockCount++;
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
    
    // If this is the first acquired lock, then we have to acquire exclusive lock
    // on the underlying file. Then increase number of acquired locks.
    if (ld->lockCount == 0 && !_LockOperation(ld, operation)) {
        // The file is not locked, so the mutex is not kept either.
        pthread_mutex_unlock(&ld->mutex);
        return NO;
    }
    ld->lockCount++;
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


#pragma mark - Foreground lock

/// Interval between attempts to acquire the lock held by another process.
static const useconds_t kLockRetryInterval = 20 * 1000;

@implementation PA2ForegroundSharedLock
{
    /// Guards the variables below together with the state of the file lock.
    NSLock * _stateLock;
    /// YES if the application is in the foreground.
    BOOL _foreground;
    /// YES if the file lock is kept by this object.
    BOOL _locked;
    /// Observers of the application state.
    NSArray * _observers;
}

- (instancetype) initWithPath:(NSString *)path error:(NSError **)error
{
    self = [super initWithPath:path recursive:NO error:error];
    if (self) {
        _stateLock = [[NSLock alloc] init];
        [self observeApplicationState];
    }
    return self;
}

- (void) dealloc
{
    for (id observer in _observers) {
        [[NSNotificationCenter defaultCenter] removeObserver:observer];
    }
}

/**
 Start tracking whether the application is in the foreground. An app extension is never treated
 as a foreground one, because the system doesn't tell the extension that it's about to be suspended.
 */
- (void) observeApplicationState
{
    // The shared application object is not available in app extensions, so it's obtained at runtime.
    Class applicationClass = NSClassFromString(@"UIApplication");
    if (!applicationClass || [[NSBundle mainBundle].bundlePath hasSuffix:@".appex"]) {
        return;
    }
    __weak PA2ForegroundSharedLock * weakSelf = self;
    NSDictionary<NSNotificationName, NSNumber*> * states = @{
        UIApplicationDidEnterBackgroundNotification : @NO,
        UIApplicationWillEnterForegroundNotification : @YES,
        UIApplicationDidBecomeActiveNotification : @YES
    };
    NSMutableArray * observers = [NSMutableArray array];
    for (NSNotificationName name in states) {
        BOOL foreground = states[name].boolValue;
        [observers addObject:[[NSNotificationCenter defaultCenter] addObserverForName:name object:nil queue:nil usingBlock:^(NSNotification * note) {
            [weakSelf setForeground:foreground];
        }]];
    }
    _observers = observers;
    // The application is treated as a background one until its state is known. The application object
    // doesn't exist yet if the SDK is configured before the application is started.
    void (^readState)(void) = ^{
        UIApplication * application = [applicationClass performSelector:@selector(sharedApplication)];
        if (application && application.applicationState != UIApplicationStateBackground) {
            [weakSelf setForeground:YES];
        }
    };
    if ([NSThread isMainThread]) {
        readState();
    } else {
        dispatch_async(dispatch_get_main_queue(), readState);
    }
}

- (void) setForeground:(BOOL)foreground
{
    [_stateLock lock];
    _foreground = foreground;
    if (!foreground && _locked) {
        // The process is not suspended before the background notification is processed,
        // so the lock is released now.
        _locked = NO;
        [super unlock];
    }
    [_stateLock unlock];
}

- (BOOL) isLocked
{
    [_stateLock lock];
    BOOL locked = _locked;
    [_stateLock unlock];
    return locked;
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
    if (_locked) {
        _locked = NO;
        [super unlock];
    }
    [_stateLock unlock];
}

/**
 Acquire the lock. The lock is kept only if the application is in the foreground. If wait is YES,
 then waits for the lock held by another process. In the background, the lock is released as soon
 as it's available. Returns NO if the lock is not available.
 */
- (BOOL) acquireAndWait:(BOOL)wait
{
    while (YES) {
        [_stateLock lock];
        BOOL foreground = _foreground;
        BOOL available = _locked || [super tryLock];
        // Wait only for the lock held by another process.
        BOOL busy = !available && errno == EWOULDBLOCK;
        if (available && !_locked) {
            if (foreground) {
                _locked = YES;
            } else {
                // The process can be suspended at any time, so the lock cannot be kept.
                [super unlock];
            }
        }
        [_stateLock unlock];
        if (!busy || !wait) {
            return available;
        }
        usleep(kLockRetryInterval);
    }
}

@end
