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

#import "PA2SharedMemory.h"
#import "PA2PrivateMacros.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma mark - Internal struct

typedef struct SharedMemory {
	int fd;
	void * ptr;
	size_t size;
	char * name;
} SharedMemory;

#define	SHM_INIT_FAIL	0		// Init failed
#define SHM_INIT_OPEN	1		// Init succeeded, no setup is needed
#define SHM_INIT_CREATE	2		// Init succeeded, setup procedure is required

#pragma mark - Public

@implementation PA2SharedMemory
{
	SharedMemory _shm;
}

- (id) initWithSharedMemoryRef:(SharedMemory *)sharedMemoryRef
{
	self = [super init];
	if (self) {
		// Take ownership of the structure
		memcpy(&_shm, sharedMemoryRef, sizeof(SharedMemory));
	} else {
		// Object allocation failed, so release the structure.
		_SharedMemoryDestroy(sharedMemoryRef, NO);
	}
	return self;
}

+ (nullable instancetype) namedSharedMemory:(nonnull NSString*)identifier
								   withSize:(NSUInteger)size
								  setupOnce:(BOOL (NS_NOESCAPE^_Nonnull)(void * _Nonnull memory, NSUInteger size, BOOL created))setupBlock
{
	// At first, try to initialize shared memory
	SharedMemory shm;
	int init_result = _SharedMemoryInit(&shm, identifier.UTF8String, size);
	if (init_result == SHM_INIT_FAIL) {
		return nil;
	}
	// Call setup block with just acquired shared memory.
	if (setupBlock(shm.ptr, shm.size, init_result == SHM_INIT_CREATE) == NO) {
		_SharedMemoryDestroy(&shm, NO);
		return nil;
	}
	// Create PA2SharedMemory and take the ownership of the SharedMemory structure.
	return [[PA2SharedMemory alloc] initWithSharedMemoryRef:&shm];
}

- (void) dealloc
{
	_SharedMemoryDestroy(&_shm, NO);
}

- (void *) bytes
{
	return _shm.ptr;
}

- (NSUInteger) size
{
	return _shm.size;
}

- (NSString*) identifier
{
	if (_shm.name) {
		return [[NSString alloc] initWithUTF8String:_shm.name];
	}
	return nil;
}

- (BOOL) isValid
{
	return _shm.fd != -1;
}

- (void) unlink
{
	_SharedMemoryDestroy(&_shm, YES);
}

#pragma mark - Private

/**
 Initialize SharedMemory structure. Rteurns
 */
static int _SharedMemoryInit(SharedMemory * shm, const char * name, size_t size)
{
	size_t name_len;
	int result_code = SHM_INIT_FAIL;
	
	shm->fd = -1;
	shm->ptr = NULL;
	shm->size = size;
	shm->name = NULL;
		
	// At first, try to open the existing shared memory.
	shm->fd = shm_open(name, O_RDWR, 0660);
	if (shm->fd == -1) {
		// If open fail and error is ENOENT, then the named shared memory doesn't exist yet.
		// Try to open and create it with exclusive flag (e.g. if it exists, then open will fail)
		if (errno == ENOENT) {
			shm->fd = shm_open(name, O_RDWR|O_CREAT|O_EXCL, 0660);
			if (shm->fd == -1) {
				// If open fails with EEXIST then it means that other process just created the shared memory
				// before us. All other errors means that something else is wrong.
				if (errno != EEXIST) {
					goto open_failure;
				}
				// One last attempt, try to open shared memory once again.
				shm->fd = shm_open(name, O_RDWR, 0660);
				if (shm->fd == -1) {
					goto open_failure;
				}
				result_code = SHM_INIT_OPEN;
			} else {
				result_code = SHM_INIT_CREATE;
			}
		} else {
			goto open_failure;
		}
	} else {
		result_code = SHM_INIT_OPEN;
	}
	
	// If shared memory is just created, then truncate its size.
	if (result_code == SHM_INIT_CREATE) {
		if (ftruncate(shm->fd, size) != 0) {
			PA2PrintErrno(@"PA2SharedMemory: ftruncate()");
			goto failure;
		}
	}
	
	// Now try to map the shared memory into this process address space.
	shm->ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, shm->fd, 0);
	if (shm->ptr == MAP_FAILED) {
		shm->ptr = NULL;
		PA2PrintErrno(@"PA2SharedMemory: mmap()");
		goto failure;
	}
	
	// Everything looks OK, so just copy the name into structure
	name_len = strlen(name) + 1;
	shm->name = (char*)malloc(name_len);
	memcpy(shm->name, name, name_len);
	
	return result_code;

open_failure:
	PA2PrintErrno(@"PA2SharedMemory: shm_open()");
	
failure:
	_SharedMemoryDestroy(shm, NO);
	return result_code;
}

/**
 Release SharedMemory structure. if unlink is YES, then also call shm_unlink()
 */
static void _SharedMemoryDestroy(SharedMemory * shm, BOOL unlink)
{
	if (shm->ptr != NULL) {
		if (munmap(shm->ptr, shm->size) != 0) {
			PA2PrintErrno(@"PA2SharedMemory: munmap()");
		}
		shm->ptr = NULL;
	}
	if (shm->fd != -1) {
		if (close(shm->fd) != 0) {
			PA2PrintErrno(@"PA2SharedMemory: close()");
		}
	}
	if (unlink && shm->name) {
		if (shm_unlink(shm->name) != 0) {
			PA2PrintErrno(@"PA2SharedMemory: shm_unlink()");
		}
	}
	if (shm->name) {
		free(shm->name);
		shm->name = NULL;
	}
}

@end
