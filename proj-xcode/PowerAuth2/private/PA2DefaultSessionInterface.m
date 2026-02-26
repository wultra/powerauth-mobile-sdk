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

#import "PA2DefaultSessionInterface.h"
#import "PA2SessionDataProvider.h"
#import <PowerAuth2/PowerAuthLog.h>
#import "PA2PrivateMacros.h"

@import PowerAuthCore;

@implementation PA2DefaultSessionInterface
{
    id<NSLocking> _lock;
    NSInteger _readWriteAccessCount;
    BOOL _saveOnUnlock;
    
    PowerAuthCoreSession * _session;
    PA2SessionDataProvider * _dataProvider;
    NSData * _stateBefore;
}

#define READ_ACCESS_LOCK()      [self lockImpl:NO]
#define READ_ACCESS_UNLOCK()    [self unlockImpl:NO]
#define WRITE_ACCESS_LOCK()     [self lockImpl:YES]
#define WRITE_ACCESS_UNLOCK()   [self unlockImpl:YES]

- (instancetype) initWithSession:(PowerAuthCoreSession*)session
                    dataProvider:(PA2SessionDataProvider*)dataProvider
{
    self = [super init];
    if (self) {
        _lock = [[NSRecursiveLock alloc] init];
        _session = session;
        _dataProvider = dataProvider;
#if DEBUG
        _session.debugMonitor = self;
#endif
    }
    return self;
}


#pragma mark - Private

- (BOOL) loadInitialState:(BOOL)cleanupOnFail
                    error:(NSError * _Nullable __autoreleasing *)error
{
    BOOL result;
    // We don't need to acquire access lock, because we're still
    // in initialization phase. We need to just temporarily simulate
    // that write access is granted.
    _readWriteAccessCount = 1;
    _saveOnUnlock = YES;
    
    NSData * statusData = [_dataProvider sessionData];
    if (statusData) {
        NSError * loadError = nil;
        switch ([_session deserializeState:statusData]) {
            case PowerAuthCoreErrorCode_Ok:
                break;
            case PowerAuthCoreErrorCode_UpgradeSDK:
                loadError = PA2MakeError(PowerAuthErrorCode_UpgradeSDK, @"Upgrade PowerAuthSDK in your application");
                break;
            default:
                loadError = PA2MakeError(PowerAuthErrorCode_InvalidActivationData, @"Unsupported activation data format");
                break;
        }
        if (loadError && error) {
            *error = loadError;
        }
        result = loadError == nil;
    } else {
        [_session resetSession:NO];
        result = YES;
    }
    _stateBefore = [_session serializedState];
    if (cleanupOnFail) {
        [_dataProvider saveSessionData:_stateBefore];
    }
    
    // Set counters to initial state
    _readWriteAccessCount = 0;
    _saveOnUnlock = NO;
    
    return result;
}

- (void) lockImpl:(BOOL)write
{
    [_lock lock];
    _readWriteAccessCount++;
    if (write) {
        _saveOnUnlock = YES;
    }
}

- (void) unlockImpl:(BOOL)write
{
    if (_readWriteAccessCount == 1 && _saveOnUnlock) {
        NSData * stateAfter = [_session serializedState];
        if (![_stateBefore isEqualToData:stateAfter]) {
            [_dataProvider saveSessionData:stateAfter];
            _stateBefore = stateAfter;
        }
        _saveOnUnlock = NO;
    }
    _readWriteAccessCount--;
    [_lock unlock];
}

#pragma mark - PA2SessionProvider

- (NSString*) activationIdentifier
{
    READ_ACCESS_LOCK();
    NSString * result = _session.activationIdentifier;
    READ_ACCESS_UNLOCK();
    return result;
}

- (id) readTaskWithSession:(id (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    READ_ACCESS_LOCK();
    id result = taskBlock(_session);
    READ_ACCESS_UNLOCK();
    return result;
}

- (BOOL) readBoolTaskWithSession:(BOOL (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    READ_ACCESS_LOCK();
    BOOL result = taskBlock(_session);
    READ_ACCESS_UNLOCK();
    return result;
}

- (void) readVoidTaskWithSession:(void (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    READ_ACCESS_LOCK();
    taskBlock(_session);
    READ_ACCESS_UNLOCK();
}

- (id) writeTaskWithSession:(id (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    WRITE_ACCESS_LOCK();
    id result = taskBlock(_session);
    WRITE_ACCESS_UNLOCK();
    return result;
}

- (BOOL) writeBoolTaskWithSession:(BOOL (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    WRITE_ACCESS_LOCK();
    BOOL result = taskBlock(_session);
    WRITE_ACCESS_UNLOCK();
    return result;
}

- (void) writeVoidTaskWithSession:(void (NS_NOESCAPE ^)(PowerAuthCoreSession *))taskBlock
{
    WRITE_ACCESS_LOCK();
    taskBlock(_session);
    WRITE_ACCESS_UNLOCK();
}

- (void) resetSession
{
    WRITE_ACCESS_LOCK();
    [_session resetSession:NO];
    WRITE_ACCESS_UNLOCK();
}

- (void) executeOutsideOfTask:(void (^)(void))block queue:(dispatch_queue_t)queue
{
    [_lock lock];
    if (_readWriteAccessCount > 0) {
        // We're in the middle of read or write task, so schedule the block execution
        // into preferred dispatch queue.
        dispatch_async(queue, ^{
            // Acquire local lock to run block safely.
            [_lock lock];
            block();
            [_lock unlock];
        });
    } else {
        // No read or write task is running in this thread, so we can execute block now.
        block();
    }
    [_lock unlock];
}

#pragma mark - PA2TokenDataLock protocol

- (BOOL) lockTokenStore
{
    WRITE_ACCESS_LOCK();
    return NO;
}

- (void) unlockTokenStore:(BOOL)contentModified
{
    WRITE_ACCESS_UNLOCK();
}

#pragma mark - PA2SessionInterface protocol

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
    return nil;
}

- (NSError*) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation
{
    return nil;
}

- (void) addOperation:(NSOperation *)operation toSharedQueue:(NSOperationQueue *)queue
{
#if DEBUG
    [_lock lock];
    if (_readWriteAccessCount > 0) {
        PowerAuthLog(@"ERROR: Adding operation to shared queue from session task can lead to interprocess deadlock.");
    }
    [_lock unlock];
#endif
    [queue addOperation:operation];
}

#pragma mark - PowerAuthSessionStatusProvider

/**
 Macro that executes PowerAuthCoreSession methodName returning BOOL while task is acquired.
 */
#define READ_BOOL_WRAPPER(methodName)                   \
- (BOOL) methodName {                                   \
    READ_ACCESS_LOCK();                                 \
    BOOL result = [_session methodName];                \
    READ_ACCESS_UNLOCK();                               \
    return result;                                      \
}

READ_BOOL_WRAPPER(hasValidActivation)
READ_BOOL_WRAPPER(canStartActivation)
READ_BOOL_WRAPPER(hasPendingActivation)
READ_BOOL_WRAPPER(hasPendingProtocolUpgrade)
READ_BOOL_WRAPPER(hasProtocolUpgradeAvailable)


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
    [_lock lock];
    if (_readWriteAccessCount == 0) {
        PowerAuthLog(@"ERROR: Read access to PowerAuthCoreSession is not granted.");
    }
    [_lock unlock];
}

- (void) requireWriteAccess
{
    [_lock lock];
    if (_readWriteAccessCount == 0 || _saveOnUnlock == NO) {
        PowerAuthLog(@"ERROR: Write access to PowerAuthCoreSession is not granted.");
    }
    [_lock unlock];
}
#endif // DEBUG

@end
