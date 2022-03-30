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

#import "PA2DefaultSessionProvider.h"
#import "PA2SessionDataProvider.h"
#import <PowerAuth2/PowerAuthLog.h>
#import "PA2PrivateMacros.h"

@import PowerAuthCore;

@implementation PA2DefaultSessionProvider
{
	/**
	 Write lock protects consistency of write operations on top of Session. This is enough
	 for the default implementation, because the underlying Session object also has its own
	 locking to protect its internal data consistency. So it's OK to do the read tasks while
	 the write lock is acquired.
	 */
	id<NSLocking> _writeLock;
	PowerAuthCoreSession * _session;
	PA2SessionDataProvider * _dataProvider;
	NSData * _stateBefore;
#if DEBUG
	NSInteger _writeAccessCount;
	NSInteger _readAccessCount;
#endif
}

#if DEBUG
	#define SET_DEBUG_MONITOR() _session.debugMonitor = self
	#define WRITE_ACCESS_INC()	_writeAccessCount++
	#define WRITE_ACCESS_DEC()	_writeAccessCount--
	#define READ_ACCESS_INC()	[_writeLock lock]; _readAccessCount++
	#define READ_ACCESS_DEC()	_readAccessCount--; [_writeLock unlock]
#else
	#define SET_DEBUG_MONITOR()
	#define WRITE_ACCESS_INC()
	#define WRITE_ACCESS_DEC()
#endif

- (instancetype) initWithSession:(PowerAuthCoreSession*)session
					dataProvider:(PA2SessionDataProvider*)dataProvider
{
	self = [super init];
	if (self) {
		_writeLock = [[NSRecursiveLock alloc] init];
		_session = session;
		_dataProvider = dataProvider;
		SET_DEBUG_MONITOR();
		[self restoreState];
	}
	return self;
}


#pragma mark - Private

- (void) restoreState
{
	// We don't need to acquire access lock, because the object is still
	// in its initialization phase. We need to just temporarily simulate
	// that write access is granted.
	WRITE_ACCESS_INC();
	NSData * statusData = [_dataProvider sessionData];
	if (statusData) {
		[_session deserializeState:statusData];
	} else {
		[_session resetSession];
	}
	_stateBefore = [_session serializedState];
	WRITE_ACCESS_DEC();
}


#pragma mark - PA2SessionProvider

- (NSString*) activationIdentifier
{
	READ_ACCESS_INC();
	NSString * result = _session.activationIdentifier;
	READ_ACCESS_DEC();
	return result;
}

- (id) readTaskWithSession:(id (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	READ_ACCESS_INC();
	id result = taskBlock(_session);
	READ_ACCESS_DEC();
	return result;
}

- (BOOL) readBoolTaskWithSession:(BOOL (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	READ_ACCESS_INC();
	BOOL result = taskBlock(_session);
	READ_ACCESS_DEC();
	return result;
}

- (void) readVoidTaskWithSession:(void (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	READ_ACCESS_INC();
	taskBlock(_session);
	READ_ACCESS_DEC();
}

- (id) writeTaskWithSession:(id (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	[_writeLock lock];
	WRITE_ACCESS_INC();
	id result = taskBlock(_session);
	NSData * stateAfter = [_session serializedState];
	if (![_stateBefore isEqualToData:stateAfter]) {
		[_dataProvider saveSessionData:stateAfter];
		_stateBefore = stateAfter;
	}
	WRITE_ACCESS_DEC();
	[_writeLock unlock];
	return result;
}

- (BOOL) writeBoolTaskWithSession:(BOOL (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	return [[self writeTaskWithSession:^id (PowerAuthCoreSession * session) {
		return @(taskBlock(_session));
	}] boolValue];
}

- (void) writeVoidTaskWithSession:(void (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
	[self writeTaskWithSession:^id (PowerAuthCoreSession * session) {
		taskBlock(_session);
		return nil;
	}];
}

- (void) resetSession
{
	[self writeTaskWithSession:^id (PowerAuthCoreSession * session) {
		[session resetSession];
		return nil;
	}];
}

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
	return nil;
}

- (NSError*) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation
{
	return nil;
}


#pragma mark - PowerAuthSessionStatusProvider

- (BOOL) canStartActivation
{
	READ_ACCESS_INC();
	BOOL result = [_session canStartActivation];
	READ_ACCESS_DEC();
	return result;
}

- (BOOL) hasPendingActivation
{
	READ_ACCESS_INC();
	BOOL result = [_session hasPendingActivation];
	READ_ACCESS_DEC();
	return result;
}

- (BOOL) hasPendingProtocolUpgrade
{
	READ_ACCESS_INC();
	BOOL result = [_session hasPendingProtocolUpgrade];
	READ_ACCESS_DEC();
	return result;
}

- (BOOL) hasProtocolUpgradeAvailable
{
	READ_ACCESS_INC();
	BOOL result = [_session hasProtocolUpgradeAvailable];
	READ_ACCESS_DEC();
	return result;
}

- (BOOL) hasValidActivation
{
	READ_ACCESS_INC();
	BOOL result = [_session hasValidActivation];
	READ_ACCESS_DEC();
	return result;
}


#if DEBUG
#pragma mark - PowerAuthCoreDebugMonitor

- (void) reportErrorCode:(PowerAuthCoreErrorCode)errorCode forOperation:(nullable NSString *)operationName
{
	NSString * errorCodeStr;
	switch (errorCode) {
		case PowerAuthCoreErrorCode_Ok: return;
		case PowerAuthCoreErrorCode_WrongParam: errorCodeStr = @"Wrong Param"; break;
		case PowerAuthCoreErrorCode_Encryption: errorCodeStr = @"Encryption failure"; break;
		case PowerAuthCoreErrorCode_WrongState: errorCodeStr = @"Wrong State"; break;
		default: errorCodeStr = [NSString stringWithFormat:@"Code %@", @(errorCode)]; break;
	}
	PowerAuthLog(@"ERROR: PowerAuthCoreSession operation failed with error %@", errorCodeStr);
}

- (void) requireReadAccess
{
	[_writeLock lock];
	if (_readAccessCount == 0 && _writeAccessCount == 0) {
		PowerAuthLog(@"ERROR: Read access to PowerAuthCoreSession is not granted.");
	}
	[_writeLock unlock];
}

- (void) requireWriteAccess
{
	[_writeLock lock];
	if (_writeAccessCount == 0) {
		PowerAuthLog(@"ERROR: Write access to PowerAuthCoreSession is not granted.");
	}
	[_writeLock unlock];
}
#endif // DEBUG

@end
