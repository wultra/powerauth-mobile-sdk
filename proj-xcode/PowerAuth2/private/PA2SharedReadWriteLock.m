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

@import PowerAuthCore;

@implementation PA2SharedReadWriteLock
{
	NSString * _fileName;
	int _fd;
}

#pragma mark - Private

#if DEBUG
static int _PrintErrno(NSString * functionName)
{
	char buffer[256];
	strerror_r(errno, buffer, sizeof(buffer));
	NSString * error = [NSString stringWithUTF8String:buffer];
	PowerAuthLog(@"%@ failed: %@", functionName, error);
}
#else
#define _PrintErrno(functionName)
#endif

static NSString * _LockPreparePath(NSString * appGroup, NSString * identifier)
{
	// Acquire URL to shared directory.
	NSURL * containerUrl = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:appGroup];
	if (!containerUrl) {
		PowerAuthLog(@"PA2SharedReadWriteLock: Failed to get container URL for app group '%@'", appGroup);
		return nil;
	}
	// Calculate hash from identifier.
	NSString * fullIdentifier = [[PowerAuthCoreCryptoUtils hashSha256:[identifier dataUsingEncoding:NSUTF8StringEncoding]] base64EncodedStringWithOptions:0];
	NSString * lockFile = [@"PowerAuthSharedLock-" stringByAppendingString:fullIdentifier];
	NSURL * fileUrl = [containerUrl	URLByAppendingPathComponent:lockFile isDirectory:NO];
	if (!fileUrl) {
		PowerAuthLog(@"PA2SharedReadWriteLock: Failed to build lock file path. App group '%@', lockFile '%@'", appGroup, lockFile);
		return nil;
	}
	return fileUrl.path;
}

static int _LockInit(NSString * lockPath)
{
	if (!lockPath) {
		return -1;
	}
	// Open file for locking
	int fd = open(lockPath.UTF8String, O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (fd == -1) {
		_PrintErrno(@"PA2SharedReadWriteLock: open()");
	}
	return fd;
}

static void _LockClose(int fd)
{
	if (fd != -1) {
		close(fd);
	}
}

static void _LockOperation(int fd, int operation)
{
	if (fd != -1) {
		int result = flock(fd, operation);
		if (result != 0) {
			_PrintErrno([NSString stringWithFormat:@"PA2SharedReadWriteLock: flock(_, %d)", operation]);
		}
	} else {
		PowerAuthLog(@"PA2SharedReadWriteLock: Invalid file descriptor");
	}
}

#pragma mark - Public

- (instancetype) initWithAppGroup:(nonnull NSString*)appGroup
					   identifier:(nonnull NSString*)identifier
{
	self = [super init];
	if (self) {
		_fileName = _LockPreparePath(appGroup, identifier);
		_fd = _LockInit(_fileName);
		if (_fd == -1) {
			return nil;
		}
	}
	return self;
}

- (void) dealloc
{
	_LockClose(fd);
}

- (void) readLock
{
	_LockOperation(_fd, LOCK_SH);
}

- (void) writeLock
{
	_LockOperation(_fd, LOCK_EX);
}

- (void) lock
{
	_LockOperation(_fd, LOCK_EX);
}

- (void) unlock
{
	_LockOperation(_fd, LOCK_UN);
}

- (void) eraseUnderlyingFile
{
	_LockClose(_fd);
	_fd = -1;
	[[NSFileManager defaultManager] removeItemAtPath:_fileName error:NULL];
}

@end
