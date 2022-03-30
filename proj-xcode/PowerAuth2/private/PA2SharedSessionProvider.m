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

#import "PA2SharedSessionProvider.h"
#import "PA2SharedLock.h"
#import "PA2SharedMemory.h"
#import "PA2PrivateConstants.h"
#import "PA2PrivateMacros.h"
#import "PA2SessionDataProvider.h"
#import "PowerAuthExternalPendingOperation+Private.h"

#import <PowerAuth2/PowerAuthLog.h>

#pragma mark - Private structures

#define TIME_TO_FINISH_EXTERNAL_OP	10.0

#define INSTANCE_ID_SIZE 	32
#define APP_ID_SIZE			(PADef_PowerAuthSharing_AppIdentifierMaxSize + 1)

#define MAG_0				'M'
#define MAG_1				'P'
#define MAG_2				'S'
#define VER_1 				'1'

/**
 The `SharedData` structure contains data shared between multiple applications.
 */
typedef struct SharedData {
	/// Contains "MPS" (Multi-Process Session) constant.
	UInt8 magic[3];
	/// Contains version of SharedData structure.
	UInt8 version;
	
	/// Bytes reserved for future use (contains 0)
	UInt8 reservedBytes[4];

	/// Counter that determine whether processes has still valid data.
	/// This value must be in sync with all LocalContext.modifyCounter.
	/// If it's not, then the process that want's to access session's data
	/// must deserialize its content from the persistent storage.
	volatile NSUInteger modifyCounter;
	
	/// Contains PowerAuthExternalPendingOperationType with type
	/// of operation started from some application. If value is 0,
	/// then no operation is started.
	volatile NSInteger specialOpType;
	/// Timestamp when the special operation has been started or last accessed
	/// by the process that started the operation.
	volatile NSTimeInterval specialOpStart;
	/// Counter that helps to resolve collisions in expired operations.
	/// Each process that starts special operation must increase this value
	/// and keep the current in LocalContext. If the local and shared value
	/// doesn't match, then some other process started its own operation.
	volatile NSUInteger specialOpTicket;
	
	/// Identifier of application that started the special operation.
	char specialOpAppId[APP_ID_SIZE];

	/// Hash calculated from PowerAuthConfiguration.instanceId
	UInt8 instanceIdentifier[INSTANCE_ID_SIZE];

} SharedData;

/**
 Structure that keeps information about local session data and the state of
 opened tasks.
 */
typedef struct LocalContext {
	/// Pointer to SharedData structure mapped to address space of this process.
	SharedData * sharedData;
	
	/// Number of opened "read" tasks from the current thread.
	NSInteger readAccessCount;
	/// Number of opened "write" tasks from the current thread.
	NSInteger writeAccessCount;
	
	/// Counter that determine whether this process has still valid data.
	/// This value must be in sync with SharedData->modfifyCounter.
	NSUInteger modifyCounter;
	/// If YES, then state of the session must be saved after the
	/// last "read" or "write" task is completed.
	BOOL saveOnUnlock;
	
	/// Contains PowerAuthExternalPendingOperationType with type
	/// of operation started from this application. If value is 0,
	/// then no operation is started in this process.
	NSInteger specialOpType;
	/// Contains
	NSUInteger specialOpTicket;
	
	/// Contains SHA256 hash calculated from PowerAuthConfiguration.instanceId.
	/// The value is used to test whether SharedData structure is mapped to
	/// the same
	UInt8 instanceIdentifier[INSTANCE_ID_SIZE];
	/// Contains length of application identifier, including nul terminating character.
	NSUInteger thisAppIdentifierSize;
	
	/// Contains application identifier.
	char thisAppIdentifier[APP_ID_SIZE];
	
} LocalContext;

#pragma mark - Public implementation

@implementation PA2SharedSessionProvider
{
	PowerAuthCoreSession * _session;
	PA2SessionDataProvider * _dataProvider;
	NSData * _stateBefore;
	
	PA2SharedMemory * _sharedMemory;
	PA2SharedLock * _sharedLock;
	id<NSLocking> _localLock;
	
	LocalContext _localContext;
}

- (instancetype) initWithSession:(PowerAuthCoreSession *)session
					dataProvider:(PA2SessionDataProvider *)dataProvider
					  instanceId:(NSString*)instanceId
				   applicationId:(NSString*)applicationId
				  sharedMemoryId:(NSString *)sharedMemoryId
				  sharedLockPath:(NSString *)sharedLockPath
{
	self = [super init];
	if (self) {
		_session = session;
		_dataProvider = dataProvider;
		
		// Initialize lock context structure
		if (!_LocalContextInit(&_localContext, instanceId, applicationId)) {
			return nil;
		}
		// Create shared lock
		_sharedLock = [[PA2SharedLock alloc] initWithPath:sharedLockPath recursive:YES];
		if (!_sharedLock) {
			return nil;
		}
		// Now acquire lock and initialize the shared memory.
		[_sharedLock lock];
		_sharedMemory = [PA2SharedMemory namedSharedMemory:sharedMemoryId withSize:sizeof(SharedData) setupOnce:^BOOL(void * memory, NSUInteger size) {
			return _InitSharedMemoryData(&_localContext, memory, size);
		}];
		// Validate allocated shared memory
		if (!_ValidateSharedMemoryData(&_localContext, _sharedMemory)) {
			[_sharedLock unlock];
			return nil;
		}
#if DEBUG
		_session.debugMonitor = self;
		_localLock = [_sharedLock createLocalRecusiveLock];
#endif
		// Everything looks OK, so restore the state and unlock the shared lock.
		[self restoreState:YES];
		
		[_sharedLock unlock];
	}
	return self;
}



#pragma mark - PowerAuthCoreSessionProvider

- (id) readTaskWithSession:(id (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:NO];
	id result = taskBlock(_session);
	[self unlockImpl:NO];
	return result;
}

- (id) writeTaskWithSession:(id  (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:YES];
	id result = taskBlock(_session);
	[self unlockImpl:YES];
	return result;
}

- (void) readVoidTaskWithSession:(void (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:NO];
	taskBlock(_session);
	[self unlockImpl:NO];
}

- (void) writeVoidTaskWithSession:(void (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:YES];
	taskBlock(_session);
	[self unlockImpl:YES];
}

- (BOOL) readBoolTaskWithSession:(BOOL (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:NO];
	BOOL result = taskBlock(_session);
	[self unlockImpl:NO];
	return result;
}

- (BOOL) writeBoolTaskWithSession:(BOOL (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	[self lockImpl:YES];
	BOOL result = taskBlock(_session);
	[self unlockImpl:YES];
	return result;
}

- (void) resetSession
{
	[self lockImpl:YES];
	[_session resetSession];
	[self unlockImpl:YES];
}

- (NSString*) activationIdentifier
{
	[self lockImpl:NO];
	NSString * result = _session.activationIdentifier;
	[self unlockImpl:NO];
	return result;
}

- (NSError *) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation
{
	[self lockImpl:YES];
	NSError * error = _LocalContextStartSpecialOp(&_localContext, externalPendingOperation);
	[self unlockImpl:YES];
	return error;
}

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
	[self lockImpl:NO];
	PowerAuthExternalPendingOperation * result;
	if (!_LocalContextThisRunningSpecialOp(&_localContext)) {
		result = _LocalContextGetExternalSpecialOp(&_localContext);
	} else {
		result = nil;
	}
	[self unlockImpl:NO];
	return result;
}



#pragma mark - PowerAuthSessionStatusProvider

- (BOOL) canStartActivation
{
	[self lockImpl:NO];
	BOOL result = [_session canStartActivation];
	[self unlockImpl:NO];
	return result;
}

- (BOOL) hasPendingActivation
{
	[self lockImpl:NO];
	BOOL result = [_session hasPendingActivation];
	[self unlockImpl:NO];
	return result;
}

- (BOOL) hasPendingProtocolUpgrade
{
	[self lockImpl:NO];
	BOOL result = [_session hasPendingProtocolUpgrade];
	[self unlockImpl:NO];
	return result;
}

- (BOOL) hasProtocolUpgradeAvailable
{
	[self lockImpl:NO];
	BOOL result = [_session hasProtocolUpgradeAvailable];
	[self unlockImpl:NO];
	return result;
}

- (BOOL) hasValidActivation
{
	[self lockImpl:NO];
	BOOL result = [_session hasValidActivation];
	[self unlockImpl:NO];
	return result;
}



#if DEBUG
#pragma mark - PowerAuthCoreDebugMonitor

- (void) reportErrorCode:(PowerAuthCoreErrorCode)errorCode forOperation:(NSString *)operationName
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
	[_localLock lock];
	if (_localContext.readAccessCount == 0 && _localContext.writeAccessCount == 0) {
		PowerAuthLog(@"ERROR: Read access to PowerAuthCoreSession is not granted.");
	}
	[_localLock unlock];
}

- (void) requireWriteAccess
{
	[_localLock lock];
	if (_localContext.writeAccessCount == 0) {
		PowerAuthLog(@"ERROR: Write access to PowerAuthCoreSession is not granted.");
	}
	[_localLock unlock];
}
#endif // DEBUG



#pragma mark - Private

/**
 Restore local session's state from the persistent storage. If force parameter
 is NO, then function try to determine whether local session needs to deserialize its state.
 If force is YES, then the session's state is always restored from the persistent storage.
 */
- (void) restoreState:(BOOL)force
{
	if (!force && !_LocalContextIsDirty(&_localContext)) {
		// Do nothing if local session has still valid data.
		return;
	}
	// Reload data from data provider
	NSData * statusData = [_dataProvider sessionData];
	if (statusData) {
		[_session deserializeState:statusData];
	} else {
		[_session resetSession];
	}
	_stateBefore = [_session serializedState];
	
	// Set context synchronized with others
	_LocalContextSynchronize(&_localContext, NO);
}

/**
 Acquire shared lock for read or write operation.
 */
- (void) lockImpl:(BOOL)write
{
	// At first, acquire a shared lock.
	[_sharedLock lock];
	
	if (_localContext.writeAccessCount == 0 && _localContext.readAccessCount == 0) {
		// First lock, we should restore session's data if needed.
		[self restoreState:NO];
	}
	
	if (write) {
		_localContext.writeAccessCount++;
		_localContext.saveOnUnlock = YES;
	} else {
		_localContext.readAccessCount++;
	}
}

/**
 Release shared lock for read or write operation.
 */
- (void) unlockImpl:(BOOL)write
{
	if (write) {
		_localContext.writeAccessCount--;
	} else {
		_localContext.readAccessCount--;
	}
#if DEBUG
	if (_localContext.writeAccessCount < 0 || _localContext.readAccessCount < 0) {
		PowerAuthLog(@"PA2SharedSessionProvider: ERROR: Internal locks & unlocks are not in pair");
	}
#endif
	if (_localContext.writeAccessCount == 0 && _localContext.readAccessCount == 0) {
		// The shared lock will be unlocked.
		if (_localContext.saveOnUnlock) {
			// Save is required, so serialize the data.
			// This must be ignored for pending protocol upgrade, because we don't want to
			// serialize the pending flag into the persistent data.
			if (!_session.hasPendingProtocolUpgrade) {
				NSData * serializedState = [_session serializedState];
				if (![serializedState isEqualToData:_stateBefore]) {
					// Data is different, so we really need to save the data.
					[_dataProvider saveSessionData:serializedState];
					_stateBefore = serializedState;
					// Notify that shared data has been changed
					_LocalContextSynchronize(&_localContext, YES);
				}
			}
		}
		if (_LocalContextThisRunningSpecialOp(&_localContext)) {
			// We keep a special operation lock. Try to determine whether it's OK to finish it automatically.
			BOOL releaseSpecialOp = NO;
			if (_localContext.specialOpType == PowerAuthExternalPendingOperationType_Activation) {
				releaseSpecialOp = !_session.hasPendingActivation;
			} else if (_localContext.specialOpType == PowerAuthExternalPendingOperationType_ProtocolUpgrade) {
				releaseSpecialOp = !_session.hasPendingProtocolUpgrade;
			}
			_LocalContextUpdateSpecialOp(&_localContext, releaseSpecialOp);
		}
	}
	// Finally, release the shared lock.
	[_sharedLock unlock];
}

#pragma mark Lock context

/**
 Initialize LocalContext structure for given instance identifier.
 */
static BOOL _LocalContextInit(LocalContext * ctx, NSString * instanceId, NSString * appId)
{
	NSData * instanceIdBytes = [PowerAuthCoreCryptoUtils hashSha256:[instanceId dataUsingEncoding:NSUTF8StringEncoding]];
	if (instanceIdBytes.length != sizeof(ctx->instanceIdentifier)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Internal error - wrong hash length");
		return NO;
	}
	NSData * appIdBytes = [appId dataUsingEncoding:NSUTF8StringEncoding];
	if (appIdBytes.length + 1 > sizeof(ctx->thisAppIdentifier)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Internal error - wrong appId length");
		return NO;
	}
	// Reset the LocalContext structure and copy identifiers.
	memset(ctx, 0, sizeof(LocalContext));
	memcpy(ctx->instanceIdentifier, instanceIdBytes.bytes, instanceIdBytes.length);
	memcpy(ctx->thisAppIdentifier, appIdBytes.bytes, appIdBytes.length);
	ctx->thisAppIdentifierSize = appIdBytes.length + 1;
	return YES;
}

/**
 Determine whether local data is dirty and session needs to reload its state from persistent storage.
 */
static BOOL _LocalContextIsDirty(LocalContext * ctx)
{
	return ctx->modifyCounter != ctx->sharedData->modifyCounter;
}
/**
 Make local context synchronized with shared data. If modified is YES, then
 also notify other applications that this context modified the shared data.
 */
static void _LocalContextSynchronize(LocalContext * ctx, BOOL modified)
{
	if (modified) {
		ctx->modifyCounter = ++ctx->sharedData->modifyCounter;
	} else {
		ctx->modifyCounter = ctx->sharedData->modifyCounter;
	}
}


#pragma mark Private special ops

/**
 Start special operation with given type. If operation cannot be started, then returns NSError.
 */
static NSError * _LocalContextStartSpecialOp(LocalContext * ctx, PowerAuthExternalPendingOperationType operationType)
{
	if (_LocalContextThisRunningSpecialOp(ctx)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Failed to start external pending operation, because operation is already running.");
		return PA2MakeError(PowerAuthErrorCode_OperationCancelled, @"Internal error: External pending operation is already started");
	}
	NSTimeInterval now = [NSDate date].timeIntervalSince1970;
	// Try to build PowerAuthExternalPendingOperation, if it's valid, then some other process running the operation.
	PowerAuthExternalPendingOperation * externalOpInfo = _LocalContextGetExternalSpecialOp(ctx);
	if (externalOpInfo) {
		// Now test whether the external operation is expired
		NSTimeInterval timeDiff = now - ctx->sharedData->specialOpStart;
		if (timeDiff >= 0.0 && timeDiff <= TIME_TO_FINISH_EXTERNAL_OP) {
			// The operation is not expired, so report the error.
			PowerAuthLog(@"PA2SharedSessionProvider: There's already external operation running in another app. External AppId = %@", externalOpInfo.externalApplicationId);
			return PA2MakeErrorInfo(PowerAuthErrorCode_ExternalPendingOperation, nil, @{PowerAuthErrorInfoKey_ExternalPendingOperation: externalOpInfo});
		}
		// External app did not finish its task in time. This process should override this with its own operation.
		PowerAuthLog(@"PA2SharedSessionProvider: External operation running in another app did not finish in time. This app will start its own operation. External AppId = %@", externalOpInfo.externalApplicationId);
	}
	
	PowerAuthLog(@"PA2SharedSessionProvider: Starting external operation with type %@", @(operationType));
	// Assign operation type to LocalContext and increase specialOpTicket.
	ctx->specialOpType = operationType;
	ctx->specialOpTicket = ++ctx->sharedData->specialOpTicket;
	// Keep time of operation start and this application's ID in SharedData.
	ctx->sharedData->specialOpStart = now;
	memcpy(ctx->sharedData->specialOpAppId, ctx->thisAppIdentifier, ctx->thisAppIdentifierSize);
	return nil;
}

/**
 Return YES if this process is running the current special operation.
 */
static BOOL _LocalContextThisRunningSpecialOp(LocalContext * ctx)
{
	if (ctx->specialOpType != 0) {
		if (ctx->specialOpType == ctx->sharedData->specialOpType &&
			ctx->specialOpTicket == ctx->sharedData->specialOpTicket) {
			return YES;
		}
		PowerAuthLog(@"PA2SharedSessionProvider: Our special operation %@ did not finish in time. Resetting local context.", @(ctx->specialOpType));
		ctx->specialOpType = 0;
	}
	return NO;
}

/**
 Update special operation running in this process. You must call _LocalContextThisRunningSpecialOp() to test
 whether this process is runnig the operation. If finish parameter is YES, then the operation is set as complete.
 */
static void _LocalContextUpdateSpecialOp(LocalContext * ctx, BOOL finish)
{
	if (finish) {
		PowerAuthLog(@"PA2SharedSessionProvider: Ending external operation with type %@", @(ctx->specialOpType));
		ctx->specialOpType = 0;
		ctx->sharedData->specialOpType = 0;
		ctx->sharedData->specialOpStart = 0.0;
		ctx->sharedData->specialOpAppId[0] = 0;
	} else {
		ctx->sharedData->specialOpStart = [NSDate date].timeIntervalSince1970;
	}
}

/**
 Return PowerAuthExternalPendingOperation if there's some running operation. This function doesn't check whether
 this process started the operation.
 */
static PowerAuthExternalPendingOperation * _LocalContextGetExternalSpecialOp(LocalContext * ctx)
{
	if (ctx->sharedData->specialOpType != 0) {
		NSString * externalApplicationId = [[NSString alloc] initWithUTF8String:ctx->sharedData->specialOpAppId];
		PowerAuthExternalPendingOperationType runningOpType = (PowerAuthExternalPendingOperationType)ctx->sharedData->specialOpType;
		return [[PowerAuthExternalPendingOperation alloc] initWithOperationType:runningOpType applicationId:externalApplicationId];
	}
	return nil;
}


#pragma mark Private shared memory

/**
 Initialize SharedData and LocalContext with provided shared memory region.
 */
static BOOL _InitSharedMemoryData(LocalContext * ctx, void * bytes, NSUInteger size)
{
	if (size < sizeof(SharedData)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Not enough bytes allocated.");
		return NO;
	}
	SharedData * sd = bytes;
	
	// Cleanup allocated memory
	memset(sd, 0, sizeof(SharedData));
	// Setup magic and version
	sd->magic[0] = MAG_0;
	sd->magic[1] = MAG_1;
	sd->magic[2] = MAG_2;
	sd->version = VER_1;
	// Set modifyCounter to 1 (different than its LocalContext counterpart)
	sd->modifyCounter = 1;
	// Set op ticket to some value.
	sd->specialOpTicket = 1;
	
	// Copy SHA256 hash calculated from PowerAuthConfiguration.instanceId to SharedData
	memcpy(sd->instanceIdentifier, ctx->instanceIdentifier, sizeof(ctx->instanceIdentifier));

	return YES;
}

/**
 Validate whether shared memory contains a valid data.
 */
static BOOL _ValidateSharedMemoryData(LocalContext * ctx, PA2SharedMemory * sharedMemory)
{
	if (!sharedMemory) {
		return NO;
	}
	if (sharedMemory.size < sizeof(SharedData)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Not enough bytes allocated.");
		return NO;
	}
	SharedData * sd = sharedMemory.bytes;
	if (sd->magic[0] != MAG_0 || sd->magic[1] != MAG_1 || sd->magic[2] != MAG_2) {
		PowerAuthLog(@"PA2SharedSessionProvider: Shared memory contains invalid data");
		return NO;
	}
	if (0 != memcmp(&ctx->instanceIdentifier[0], &sd->instanceIdentifier[0], sizeof(ctx->instanceIdentifier))) {
		PowerAuthLog(@"PA2SharedSessionProvider: Shared memory contains different activation data");
		return NO;
	}
	if (sd->version != VER_1) {
		PowerAuthLog(@"PA2SharedSessionProvider: Unsupported shared data version");
		return NO;
	}
	// Keep pointer to shared memory in LockContext
	ctx->sharedData = sd;
	return YES;
}

@end
