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

#import "PA2SharedSessionInterface.h"
#import "PA2SharedLock.h"
#import "PA2SharedMemory.h"
#import "PA2PrivateConstants.h"
#import "PA2PrivateMacros.h"
#import "PA2SessionDataProvider.h"
#import "PowerAuthExternalPendingOperation+Private.h"

#import <PowerAuth2/PowerAuthLog.h>

#pragma mark Private constants

/// Lenght of SHA256 hash, calculated from PowerAuthConfiguration.instanceId
#define INSTANCE_ID_SIZE 	32

/// Length of application identifier, reserved in SharedData.
#define APP_ID_SIZE			(PADef_PowerAuthSharing_AppIdentifierMaxSize + 1)
/// Magic constant used at the beginning of SharedData structure.
#define MAG_0				'M'
#define MAG_1				'P'
#define MAG_2				'S'
/// Version of SharedData structure.
#define VER_1 				'1'

/// Defines how long will other processes wait until to re-take special operation ownership.
#define TIME_TO_FINISH_EXTERNAL_OP	10.0

#pragma mark - Private structures

///
/// The `SharedData` structure contains data shared between multiple applications.
///
typedef struct SharedData {
	/// Contains "MPS" (Multi-Process Session) constant.
	UInt8 magic[3];
	/// Contains version of SharedData structure.
	UInt8 version;
	
	/// Bytes reserved for future use (contains 0)
	UInt8 reservedBytes[4];

	/// Counter that determine whether processes has still valid data.
	/// This value must be in sync with all LocalContext.stateModifyCounter.
	/// If it's not, then the process that want's to access session's data
	/// must deserialize its content from the persistent storage.
	volatile NSUInteger stateModifyCounter;
	/// Counter that determine whether processes has still valid data.
	/// This value must be in sync with all LocalContext.tokenModifyCounter.
	/// If it's not, then the process that want's to access tokens's data
	/// must deserialize its content from the persistent storage.
	volatile NSUInteger tokenModifyCounter;
	
	/// Reserved variables for future use.
	NSUInteger reservedValues[6];
	
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

///
/// Structure that keeps information about local session data and the state of
/// opened tasks.
///
typedef struct LocalContext {
	/// Pointer to SharedData structure mapped to address space of this process.
	SharedData * sharedData;

	/// Counter that determine whether this process has still valid data.
	/// This value must be in sync with SharedData->stateModifyCounter.
	NSUInteger stateModifyCounter;
	/// Counter that determine whether this process has still valid data.
	/// This value must be in sync with SharedData->tokenModifyCounter.
	NSUInteger tokenModifyCounter;
	
	/// Contains PowerAuthExternalPendingOperationType with type
	/// of operation started from this application. If value is 0,
	/// then no operation is started in this process.
	NSInteger specialOpType;
	/// Counter that helps to determine whether this process still owns
	/// the special operation. If this counter is not equal to value in
	/// SharedData, then this application lost ownership of the special operation.
	NSUInteger specialOpTicket;
	
	/// Contains SHA256 hash calculated from PowerAuthConfiguration.instanceId.
	/// The value is used to test whether SharedData structure is mapped to
	/// the same PowerAuthSDK instance.
	UInt8 instanceIdentifier[INSTANCE_ID_SIZE];
	/// Contains length of application identifier, including nul terminating character.
	NSUInteger thisAppIdentifierSize;
	
	/// Contains application identifier.
	char thisAppIdentifier[APP_ID_SIZE];
	
} LocalContext;

#pragma mark - Public implementation

@implementation PA2SharedSessionInterface
{
	/// Reference to PowerAuthCoreSession provided by this object.
	PowerAuthCoreSession * _session;
	/// Reference to object providing data for session.
	PA2SessionDataProvider * _dataProvider;
	/// Last serialized state.
	NSData * _stateBefore;
	/// Object holding memory shared between applications
	PA2SharedMemory * _sharedMemory;
	/// Lock shared between applications that guards access to activation status data.
	PA2SharedLock * _sharedLock;
	/// Lock shared between applications that allows the signed requests serialization.
	PA2SharedLock * _queueLock;
	/// Additional debug lock, used for DEBUG builds
	id<NSLocking> _debugLock;
	
	/// Number of "read" and "write" tasks opened from the current thread.
	NSInteger _readWriteAccessCount;
	/// If YES, then state of the session must be saved after the
	/// last "read" or "write" task is completed.
	BOOL _saveOnUnlock;
	/// If YES, then "write" access is temporarily granted due to fact that
	/// provider needs to restore session's state even when task is read-only.
	BOOL _internalAccessGranted;
	
	/// LocalContext structure
	LocalContext _localContext;
}

- (instancetype) initWithSession:(PowerAuthCoreSession *)session
					dataProvider:(PA2SessionDataProvider *)dataProvider
					  instanceId:(NSString *)instanceId
				   applicationId:(NSString *)applicationId
				  sharedMemoryId:(NSString *)sharedMemoryId
				  statusLockPath:(NSString *)statusLockPath
				   queueLockPath:(NSString *)queueLockPath
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
		_sharedLock = [[PA2SharedLock alloc] initWithPath:statusLockPath recursive:YES];
		if (!_sharedLock) {
			return nil;
		}
		_queueLock = [[PA2SharedLock alloc] initWithPath:queueLockPath recursive:NO];
		if (!_queueLock) {
			return nil;
		}
		// Now acquire lock and initialize the shared memory.
		[_sharedLock lock];
		_sharedMemory = [PA2SharedMemory namedSharedMemory:sharedMemoryId withSize:sizeof(SharedData) setupOnce:^BOOL(void * memory, NSUInteger size, BOOL created) {
			if (created) {
				// This is the first process that created the shared memory, so initialize its content
				return _InitSharedMemoryData(&_localContext, memory, size);
			} else {
				// If shared memory was already initialized, then just validate its content.
				return _ValidateSharedMemoryData(&_localContext, memory, size);
			}
		}];
		// Validate allocated shared memory
		if (!_sharedMemory) {
			[_sharedLock unlock];
			return nil;
		}
#if DEBUG
		// Assign this class as session's debug monitor
		_session.debugMonitor = self;
		// Acquire local recursive lock to get a thread safety for monitor functions
		_debugLock = [_sharedLock createLocalRecusiveLock];
#endif
		// Everything looks OK, so restore the state and unlock the shared lock.
		[self loadState:YES];
		
		// Finally, release the shared lock
		[_sharedLock unlock];
	}
	return self;
}

/**
 READ_BLOCK macro all its parameters expands between [self lockImpl:NO] and [self unlockImpl:NO].
 */
#define READ_BLOCK(...)		[self lockImpl:NO]; 	\
							__VA_ARGS__; 			\
							[self unlockImpl:NO];
/**
 WRITE_BLOCK macro all its parameters expands between [self lockImpl:YES] and [self unlockImpl:YES].
 */
#define WRITE_BLOCK(...)	[self lockImpl:YES]; 	\
							__VA_ARGS__; 			\
							[self unlockImpl:YES];

#pragma mark - PowerAuthCoreSessionProvider protocol

- (id) writeTaskWithSession:(id  (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	WRITE_BLOCK(id result = taskBlock(_session));
	return result;
}

- (void) writeVoidTaskWithSession:(void (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	WRITE_BLOCK(taskBlock(_session));
}

- (BOOL) writeBoolTaskWithSession:(BOOL (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	WRITE_BLOCK(BOOL result = taskBlock(_session));
	return result;
}

- (id) readTaskWithSession:(id (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	READ_BLOCK(id result = taskBlock(_session));
	return result;
}

- (void) readVoidTaskWithSession:(void (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	READ_BLOCK(taskBlock(_session));
}

- (BOOL) readBoolTaskWithSession:(BOOL (NS_NOESCAPE^)(PowerAuthCoreSession *))taskBlock
{
	READ_BLOCK(BOOL result = taskBlock(_session));
	return result;
}

- (void) resetSession
{
	WRITE_BLOCK([_session resetSession])
}

- (NSString*) activationIdentifier
{
	READ_BLOCK(NSString * result = _session.activationIdentifier);
	return result;
}

#pragma mark - PA2TokenDataLock protocol

- (BOOL) lockTokenStore
{
	[self lockImpl:YES];
	return _LocalContextTokenIsDirty(&_localContext);
}

- (void) unlockTokenStore:(BOOL)contentModified
{
	_LocalContextTokenSynchronize(&_localContext, contentModified);
	[self unlockImpl:YES];
}

#pragma mark - PA2SessionInterface protocol

- (NSError *) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation
{
	WRITE_BLOCK(NSError * result = _LocalContextStartSpecialOp(&_localContext, externalPendingOperation));
	return result;
}

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
	READ_BLOCK
	(PowerAuthExternalPendingOperation * result;
	 if (!_LocalContextThisRunningSpecialOp(&_localContext)) {
		 result = _LocalContextGetExternalSpecialOp(&_localContext);
	 } else {
		 result = nil;
	 });
	return result;
}

- (BOOL) supportsSharedQueueLock
{
	return YES;
}

- (void) addOperation:(NSOperation*)operation toSharedQueue:(NSOperationQueue*)queue
{
#if DEBUG
	[_debugLock lock];
	if (_readWriteAccessCount > 0) {
		PowerAuthLog(@"ERROR: Adding operation to shared queue from session task can lead to interprocess deadlock.");
	}
	[_debugLock unlock];
#endif // DEBUG
	NSBlockOperation * addOperation = [NSBlockOperation blockOperationWithBlock:^{
		if (!operation.cancelled) {
			NSBlockOperation * lockOp = [NSBlockOperation blockOperationWithBlock:^{ [_queueLock lock]; }];
			NSBlockOperation * unlockOp = [NSBlockOperation blockOperationWithBlock:^{ [_queueLock unlock]; }];
		
			[operation addDependency:lockOp];
			[unlockOp addDependency:operation];
			
			[queue addOperation:lockOp];
			[queue addOperation:operation];
			[queue addOperation:unlockOp];
		}
	}];
	addOperation.queuePriority = NSOperationQueuePriorityVeryHigh;
	[queue addOperation:addOperation];
}

#pragma mark - PowerAuthSessionStatusProvider protocol

/**
 Macro that executes PowerAuthCoreSession methodName returning BOOL while task is acquired.
 */
#define READ_BOOL_WRAPPER(methodName)					\
- (BOOL) methodName {									\
	READ_BLOCK(BOOL result = [_session methodName]);	\
	return result;										\
}

READ_BOOL_WRAPPER(hasValidActivation)
READ_BOOL_WRAPPER(canStartActivation)
READ_BOOL_WRAPPER(hasPendingActivation)
READ_BOOL_WRAPPER(hasPendingProtocolUpgrade)
READ_BOOL_WRAPPER(hasProtocolUpgradeAvailable)


#if DEBUG
#pragma mark - PowerAuthCoreDebugMonitor protocol

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
	[_debugLock lock];
	// Determine whether there's some opened task
	BOOL accessGranted = _readWriteAccessCount > 0 || _internalAccessGranted;
	if (!accessGranted) {
		PowerAuthLog(@"ERROR: Read access to PowerAuthCoreSession is not granted.");
	}
	[_debugLock unlock];
}

- (void) requireWriteAccess
{
	[_debugLock lock];
	BOOL accessGranted = (_readWriteAccessCount > 0 && _saveOnUnlock) || _internalAccessGranted;
	if (!accessGranted) {
		PowerAuthLog(@"ERROR: Write access to PowerAuthCoreSession is not granted.");
	}
	[_debugLock unlock];
}
#endif // DEBUG



#pragma mark - Private methods

/**
 Load local session's state from the persistent storage. If force parameter
 is NO, then function try to determine whether local session needs to deserialize its state.
 If force is YES, then the session's state is always restored from the persistent storage.
 */
- (void) loadState:(BOOL)force
{
	if (!force && !_LocalContextStateIsDirty(&_localContext)) {
		// Do nothing if local session has still valid data.
		return;
	}
	
	// Temporarily allow call session's methods that require write access.
	_internalAccessGranted = YES;
	
	// Reload data from data provider
	NSData * statusData = [_dataProvider sessionData];
	if (statusData) {
		[_session deserializeState:statusData];
	} else {
		[_session resetSession];
	}
	_stateBefore = [_session serializedState];
	
	// Clear temporary granted access.
	_internalAccessGranted = NO;
	// Set context synchronized with others
	_LocalContextStateSynchronize(&_localContext, NO);
}

/**
 Save session's state to the persistent storage.
 */
- (void) saveState
{
	NSData * serializedState = [_session serializedState];
	if (![serializedState isEqualToData:_stateBefore]) {
		// Data is different, so we really need to save the data.
		[_dataProvider saveSessionData:serializedState];
		_stateBefore = serializedState;
		// Notify that shared data has been changed
		_LocalContextStateSynchronize(&_localContext, YES);
	}
}

/**
 Acquire shared lock for read or write operation.
 */
- (void) lockImpl:(BOOL)write
{
	// At first, acquire a shared lock.
	[_sharedLock lock];
	
	_readWriteAccessCount++;
	if (write) {
		_saveOnUnlock = YES;
	}
	
	if (_readWriteAccessCount == 1) {
		// First lock, we should restore session's data if needed.
		[self loadState:NO];
	}
}

/**
 Release shared lock for read or write operation.
 */
- (void) unlockImpl:(BOOL)write
{
	if (_readWriteAccessCount == 1) {
		// The shared lock will be released at the end of this function.
		// At first, save the session's state if there was some write task opened.
		if (_saveOnUnlock) {
			[self saveState];
			_saveOnUnlock = NO;
		}
		// Now determine whether it's possible to end the special operation started in this process.
		if (_LocalContextThisRunningSpecialOp(&_localContext)) {
			// We keep a special operation lock. Try to determine whether it's OK to finish it automatically.
			BOOL finishSpecialOp = NO;
			if (_localContext.specialOpType == PowerAuthExternalPendingOperationType_Activation) {
				finishSpecialOp = !_session.hasPendingActivation;
			} else if (_localContext.specialOpType == PowerAuthExternalPendingOperationType_ProtocolUpgrade) {
				finishSpecialOp = !_session.hasPendingProtocolUpgrade;
			}
			_LocalContextUpdateSpecialOp(&_localContext, finishSpecialOp);
		}
	}
	_readWriteAccessCount--;
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
 Determine whether local state data is dirty and session needs to reload its state from persistent storage.
 */
static BOOL _LocalContextStateIsDirty(LocalContext * ctx)
{
	return ctx->stateModifyCounter != ctx->sharedData->stateModifyCounter;
}

/**
 Make local context synchronized with shared sate data. If modified is YES, then
 also notify other applications that this context modified the shared state data.
 */
static void _LocalContextStateSynchronize(LocalContext * ctx, BOOL modified)
{
	if (modified) {
		ctx->stateModifyCounter = ++ctx->sharedData->stateModifyCounter;
	} else {
		ctx->stateModifyCounter = ctx->sharedData->stateModifyCounter;
	}
}

/**
 Determine whether local state data is dirty and session needs to reload its state from persistent storage.
 */
static BOOL _LocalContextTokenIsDirty(LocalContext * ctx)
{
	return ctx->tokenModifyCounter != ctx->sharedData->tokenModifyCounter;
}

/**
 Make local context synchronized with shared token data. If modified is YES, then
 also notify other applications that this context modified the shared token data.
 */
static void _LocalContextTokenSynchronize(LocalContext * ctx, BOOL modified)
{
	if (modified) {
		ctx->tokenModifyCounter = ++ctx->sharedData->tokenModifyCounter;
	} else {
		ctx->tokenModifyCounter = ctx->sharedData->tokenModifyCounter;
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
	ctx->sharedData->specialOpType = operationType;
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
		memset(ctx->sharedData->specialOpAppId, 0, sizeof(ctx->sharedData->specialOpAppId));
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
	if (!bytes || size < sizeof(SharedData)) {
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
	// Set modifyCounters to 1 (different than their LocalContext counterparts)
	sd->stateModifyCounter = 1;
	sd->tokenModifyCounter = 1;
	// Set op ticket to some value.
	sd->specialOpTicket = 1;
	
	// Copy SHA256 hash calculated from PowerAuthConfiguration.instanceId to SharedData
	memcpy(sd->instanceIdentifier, ctx->instanceIdentifier, sizeof(ctx->instanceIdentifier));
	
	// Keep pointer to shared memory in LockContext
	ctx->sharedData = sd;
	return YES;
}

/**
 Validate whether shared memory contains a valid data.
 */
static BOOL _ValidateSharedMemoryData(LocalContext * ctx, void * bytes, NSUInteger size)
{
	if (!bytes || size < sizeof(SharedData)) {
		PowerAuthLog(@"PA2SharedSessionProvider: Not enough bytes allocated.");
		return NO;
	}
	SharedData * sd = bytes;
	
	// Validate magic values
	if (sd->magic[0] != MAG_0 || sd->magic[1] != MAG_1 || sd->magic[2] != MAG_2) {
		PowerAuthLog(@"PA2SharedSessionProvider: Shared memory contains invalid data");
		return NO;
	}
	// Compare instance identifiers
	if (0 != memcmp(ctx->instanceIdentifier, sd->instanceIdentifier, sizeof(ctx->instanceIdentifier))) {
		PowerAuthLog(@"PA2SharedSessionProvider: Shared memory contains different activation data");
		return NO;
	}
	// Finally, compare version
	if (sd->version != VER_1) {
		PowerAuthLog(@"PA2SharedSessionProvider: Unsupported shared data version");
		return NO;
	}
	// Keep pointer to shared memory in LockContext
	ctx->sharedData = sd;
	return YES;
}

@end
