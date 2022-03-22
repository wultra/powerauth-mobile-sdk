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

#import "PA2SharedReadWriteLock.h"
#import <PowerAuth2/PowerAuthLog.h>
#include <pthread.h>

@import PowerAuthCore;

/**
 Internal structure keeping lock data.
 */
typedef struct LockData {
	/**
	 Pointer to function that implements lock function.
	 */
	void (*lockFunc)(struct LockData * data, BOOL isWrite);
	/**
	 Pointer to function that implements unlock function.
	 */
	void (*unlockFunc)(struct LockData * data, BOOL isWrite);
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
	 mutex implementation.
	 */
	pthread_mutex_t mutex;
	/**
	 How many read locks has been acquired for this thread.
	 */
	int readLockCount;
	/**
	 How many write locks has been acquired for this thread.
	 */
	int writeLockCount;
	
} LockData;


@implementation PA2SharedReadWriteLock
{
	LockData _lockData;
}

static BOOL _LockInit(NSString * lockPath, BOOL recursive, LockData * lockData);

#pragma mark - Public interface

- (instancetype) initWithPath:(NSString *)path recursive:(BOOL)recursive
{
	self = [super init];
	if (self) {
		if (_LockInit(path, recursive, &_lockData) == NO) {
			PowerAuthLog(@"PA2SharedReadWriteLock: Failed to initialize lock");
			return nil;
		}
	}
	return self;
}

- (void) dealloc
{
	_lockData.closeFunc(&_lockData);
}

- (void) readLock
{
	_lockData.lockFunc(&_lockData, NO);
}

- (void) readUnlock
{
	_lockData.unlockFunc(&_lockData, NO);
}

- (void) writeLock
{
	_lockData.lockFunc(&_lockData, YES);
}

- (void) writeUnlock
{
	_lockData.unlockFunc(&_lockData, YES);
}

- (void) lock
{
	_lockData.lockFunc(&_lockData, YES);
}

- (void) unlock
{
	_lockData.unlockFunc(&_lockData, YES);
}


#pragma mark - Private

#if DEBUG
static void _PrintErrno(NSString * functionName)
{
	char buffer[256];
	strerror_r(errno, buffer, sizeof(buffer));
	NSString * error = [NSString stringWithUTF8String:buffer];
	PowerAuthLog(@"%@ failed: %@", functionName, error);
}
#else
#define _PrintErrno(functionName)
#endif

static void _LockSimple(LockData *, BOOL);
static void _UnlockSimple(LockData *, BOOL);
static void _CloseSimple(LockData *);
static void _LockRecursive(LockData *, BOOL);
static void _UnlockRecursive(LockData *, BOOL);
static void _CloseRecursive(LockData *);

/**
 Initialize LockData structure for given file and lock type.
 */
static BOOL _LockInit(NSString * lockPath, BOOL recursive, LockData * lockData)
{
	memset(lockData, 0, sizeof(LockData));
	lockData->fileDescriptor = -1;

	if (recursive) {
		lockData->lockFunc   = _LockRecursive;
		lockData->unlockFunc = _UnlockRecursive;
		lockData->closeFunc  = _CloseRecursive;
	} else {
		lockData->lockFunc   = _LockSimple;
		lockData->unlockFunc = _UnlockSimple;
		lockData->closeFunc  = _CloseSimple;
	}
	
	BOOL result = NO;
	do {
		// Open file for locking
		lockData->fileDescriptor = open(lockPath.UTF8String, O_CREAT | O_TRUNC | O_RDWR, 0666);
		if (lockData->fileDescriptor == -1) {
			_PrintErrno(@"PA2SharedReadWriteLock: open()");
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
				_PrintErrno(@"PA2SharedReadWriteLock: pthread_mutex_init()");
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

static void _LockOperation(LockData * ld, int operation)
{
	if (ld->fileDescriptor != -1) {
		int result = flock(ld->fileDescriptor, operation);
		if (result != 0) {
			_PrintErrno([NSString stringWithFormat:@"PA2SharedReadWriteLock: flock(_, %d)", operation]);
		}
	}
}

#pragma mark - Simple lock

static void _LockSimple(LockData * ld, BOOL isWrite)
{
	// The simple implementation just try to acquire file lock.
	_LockOperation(ld, isWrite ? LOCK_EX : LOCK_SH);
}

static void _UnlockSimple(LockData * ld, BOOL isWrite)
{
	// The simple implementation just release an acquired lock.
	_LockOperation(ld, LOCK_UN);
}

static void _CloseSimple(LockData * ld)
{
	// Close file if we're still have the file descriptor.
	if (ld->fileDescriptor != -1) {
		close(ld->fileDescriptor);
		ld->fileDescriptor = -1;
	}
}

#pragma mark - Recursive lock

static void _LockRecursive(LockData * ld, BOOL isWrite)
{
	// At first, acquire recursive mutex for this thread.
	if (!ld->mutexInitialized) {
		return;
	}
	if (pthread_mutex_lock(&ld->mutex) != 0) {
		_PrintErrno(@"PA2SharedReadWriteLock: pthread_mutex_lock()");
		return;
	}
	
	int sharedLockOperation = 0;
	if (isWrite) {
		// Increase number of write locks. If count is 1, then we have to acquire
		// exclusive lock on the underlying file.
		ld->writeLockCount++;
		if (ld->writeLockCount == 1) {
			sharedLockOperation = LOCK_EX;
		}
	} else {
		// Increase number of read locks. If count is 1 and there's no write lock,
		// then we have to acquire an exclusive lock on the underlying file.
		ld->readLockCount++;
		if (ld->readLockCount == 1 && ld->writeLockCount == 0) {
			sharedLockOperation = LOCK_SH;
		}
	}
	if (sharedLockOperation != 0) {
		_LockOperation(ld, sharedLockOperation);
	}
}

static void _UnlockRecursive(LockData * ld, BOOL isWrite)
{
	if (!ld->mutexInitialized) {
		return;
	}
	// At first, decrement appropriate counter.
	if (isWrite) {
		ld->writeLockCount--;
	} else {
		ld->readLockCount--;
	}
	// If both counters are equal to 0, then we can also release the underlying file lock.
	if (ld->readLockCount == 0 && ld->writeLockCount == 0) {
		_LockOperation(ld, LOCK_UN);
	}
	if (ld->readLockCount < 0 || ld->writeLockCount < 0) {
		PowerAuthLog(@"PA2SharedReadWriteLock: lock* - unlock* functions are not in pair.");
	}
	// And finally, release recursive pthread mutex.
	if (pthread_mutex_unlock(&ld->mutex) != 0) {
		_PrintErrno(@"PA2SharedReadWriteLock: pthread_mutex_unlock()");
	}
}

static void _CloseRecursive(LockData * ld)
{
	// Destroy mutex if it's still initialized.
	if (ld->mutexInitialized == YES) {
		pthread_mutex_destroy(&ld->mutex);
		ld->mutexInitialized = NO;
	}
	// Close file descriptor
	_CloseSimple(ld);
}

@end
