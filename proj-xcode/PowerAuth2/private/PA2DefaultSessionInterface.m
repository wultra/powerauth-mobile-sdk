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
    
    // Services
    PA2KeystoreService * _keystoreService;
    PA2TimeSynchronizationService * _timeService;
}

#define READ_ACCESS_LOCK()                      \
    [self lockImpl:NO];

#define READ_ACCESS_UNLOCK(err, lerr)           \
if (![self unlockImpl:&lerr] || lerr) {         \
        PA2WrapError(lerr, err);                \
    }

#define WRITE_ACCESS_LOCK()                     \
    [self lockImpl:YES];

#define WRITE_ACCESS_UNLOCK(err, lerr)          \
    if (![self unlockImpl:&lerr] || lerr) {     \
        PA2WrapError(lerr, err);                \
    }


- (instancetype) initWithSession:(PowerAuthCoreSession*)session
                    dataProvider:(PA2SessionDataProvider*)dataProvider
                           error:(NSError**)error;
{
    self = [super init];
    if (self) {
        _lock = [[NSRecursiveLock alloc] init];
        _session = session;
        _dataProvider = dataProvider;
    }
    return self;
}

- (void) releaseResourcesBeforeDestroy
{
}

- (BOOL) loadInitialState:(BOOL)clearUnsupportedData
                    error:(NSError*_Nullable*_Nullable)error
{
    // We don't need to acquire access lock, because the object is still
    // in its initialization phase. We need to just temporarily simulate
    // that write access is granted.
    _readWriteAccessCount = 1;
    _saveOnUnlock = YES;
    
    NSError * localError = nil;
    NSData * statusData = [_dataProvider sessionData];
    BOOL loadSuccess;
    if (statusData) {
        loadSuccess = [_session deserializeState:statusData error:&localError];
        if (!loadSuccess) {
            PowerAuthCoreError coreError = localError.powerAuthCoreErrorCode;
            if (clearUnsupportedData && (coreError == PowerAuthCoreError_InvalidActivationData || coreError == PowerAuthCoreError_UpgradeSDK)) {
                // If cleanup is requested, then ignore the error and reset the session
                [_session resetSession];
                loadSuccess = YES;
            } else {
                // Otherwise wrap
                PA2WrapError(localError, error);
            }
        }
    } else {
        [_session resetSession];
        loadSuccess = YES;
    }
    if (loadSuccess) {
        _stateBefore = statusData;
    }
    
    // Set counters to initial state
    _readWriteAccessCount = 0;
    _saveOnUnlock = NO;
    
    return loadSuccess;
}


#pragma mark - Private

- (void) lockImpl:(BOOL)write
{
    [_lock lock];
    _readWriteAccessCount++;
    if (write) {
        _saveOnUnlock = YES;
    }
}

- (BOOL) unlockImpl:(NSError**)error
{
    BOOL result = YES;
    if (_readWriteAccessCount == 1 && _saveOnUnlock) {
        if (!(error && *error)) {
            // No error
            NSData * stateAfter = [_session serializedState:error];
            if (stateAfter) {
                if (![_stateBefore isEqualToData:stateAfter]) {
                    [_dataProvider saveSessionData:stateAfter];
                    _stateBefore = stateAfter;
                }
                _saveOnUnlock = NO;
            } else {
                result = NO;
            }
        } else {
            // there's already error. skip save and set result to NO
            result = NO;
        }
    }
    _readWriteAccessCount--;
    [_lock unlock];
    return result;
}

#pragma mark - PowerAuthCoreSessionProvider

- (NSString*) activationIdentifier
{
    [self lockImpl:NO];
    NSString * result = _session.activationIdentifier;
    [self unlockImpl:nil];
    return result;
}

- (id) readTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBlock)taskBlock error:(NSError**)error
{
    READ_ACCESS_LOCK();
    NSError * localError = nil;
    id result = taskBlock(_session, &localError);
    READ_ACCESS_UNLOCK(error, localError);
    return result;
}

- (BOOL) readBoolTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBoolBlock)taskBlock error:(NSError**)error
{
    READ_ACCESS_LOCK();
    NSError * localError = nil;
    BOOL result = taskBlock(_session, &localError);
    READ_ACCESS_UNLOCK(error, localError);
    return result;
}

- (id) writeTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBlock)taskBlock error:(NSError**)error
{
    WRITE_ACCESS_LOCK();
    NSError * localError = nil;
    id result = taskBlock(_session, &localError);
    WRITE_ACCESS_UNLOCK(error, localError);
    return result;
}

- (BOOL) writeBoolTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBoolBlock)taskBlock error:(NSError**)error
{
    WRITE_ACCESS_LOCK();
    NSError * localError = nil;
    BOOL result = taskBlock(_session, &localError);
    WRITE_ACCESS_UNLOCK(error, localError);
    return result && !localError;
}

- (BOOL) resetSession:(NSError**)error
{
    WRITE_ACCESS_LOCK();
    [_session resetSession];
    NSError * localError = nil;
    WRITE_ACCESS_UNLOCK(error, localError);
    return !localError;
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

- (BOOL) lockTokenStore:(BOOL*)dirty error:(NSError**)error
{
    WRITE_ACCESS_LOCK();
    if (error) *error = nil;
    if (dirty) *dirty = NO;
    return YES;
}

- (BOOL) unlockTokenStore:(BOOL)contentModified error:(NSError **)error
{
    NSError * localError = nil;
    WRITE_ACCESS_UNLOCK(error, localError);
    return !localError;
}

#pragma mark - PA2SessionInterface protocol

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
    return nil;
}

- (BOOL) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation error:(NSError **)error
{
    if (error) *error = nil;
    return YES;
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

// services

static void _ThrowInternalInitFail(void)
{
    extern NSString *const PowerAuthExceptionMissingConfig;
    [NSException raise:PowerAuthExceptionMissingConfig format:@"Broken PowerAuthSDK services initialization sequence"];
}


- (PA2KeystoreService*) keystoreService
{
    if (!_keystoreService) {
        _ThrowInternalInitFail();
    }
    return _keystoreService;
}

- (PA2TimeSynchronizationService*) timeSynchronizationService
{
    if (!_timeService) {
        _ThrowInternalInitFail();
    }
    return _timeService;
}

- (void) connectWithKeystoreService:(nonnull PA2KeystoreService*)keystoreService
                        timeService:(nonnull PA2TimeSynchronizationService*)timeService
{
    if (_timeService || _keystoreService) {
        _ThrowInternalInitFail();
    }
    _keystoreService = keystoreService;
    _timeService = timeService;
}


#pragma mark - PowerAuthSessionStatusProvider

- (BOOL) hasValidActivation
{
    return [self readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [session hasValidActivationData];
    } error:nil];
}

- (BOOL) canStartActivation
{
    return [self readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [session canCreateActivation];
    } error:nil];
}

- (BOOL) hasPendingActivation
{
    return [self readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [session hasPendingCreateActivation];
    } error:nil];
}

- (BOOL) hasPendingProtocolUpgrade
{
    return [self readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [session hasPendingProtocolUpgrade];
    } error:nil];
}

- (BOOL) hasProtocolUpgradeAvailable
{
    return [self readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [session hasProtocolUpgradeAvailable];
    } error:nil];
}

#pragma mark - PowerAuthCoreSessionDelegate

- (BOOL) requireReadAccess
{
    [_lock lock];
    BOOL accessGranted = _readWriteAccessCount > 0;
    [_lock unlock];
    return accessGranted;
}

- (BOOL) requireWriteAccess
{
    [_lock lock];
    BOOL accessGranted = _readWriteAccessCount > 0 && _saveOnUnlock;
    [_lock unlock];
    return accessGranted;
}

@end
