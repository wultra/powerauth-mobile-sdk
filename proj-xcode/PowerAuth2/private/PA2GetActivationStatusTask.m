/**
 * Copyright 2021 Wultra s.r.o.
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

#import "PA2GetActivationStatusTask.h"
#import "PowerAuthActivationStatus+Private.h"
#import "PA2PrivateMacros.h"
#import "PA2RestApiObjects.h"
#import "PA2RestApiEndpoint.h"
#import "PA2HttpClient.h"
#import "PA2Result.h"

#import <PowerAuth2/PowerAuthLog.h>
#import <PowerAuth2/PowerAuthAuthentication.h>

@import PowerAuthCore;

#pragma mark - Status fetching task

@implementation PA2GetActivationStatusTask
{
    PA2HttpClient * _client;
    NSData * _deviceRelatedKey;
    id<PowerAuthCoreSessionProvider> _sessionProvider;
    __weak id<PA2GetActivationStatusTaskDelegate> _delegate;
    BOOL _disableUpgrade;
    
    // Runtime variables
    NSInteger _upgradeAttempts;
    BOOL _disableAutoCancel;
    PowerAuthActivationStatus * _receivedStatus;
}

- (id) initWithHttpClient:(PA2HttpClient*)httpClient
         deviceRelatedKey:(NSData*)deviceRelatedKey
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2GetActivationStatusTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
           disableUpgrade:(BOOL)disableUpgrade
{
    self = [super initWithSharedLock:sharedLock taskName:@"GetActivationStatus"];
    if (self) {
        _client = httpClient;
        _deviceRelatedKey = deviceRelatedKey;
        _sessionProvider = sessionProvider;
        _delegate = delegate;
        _disableUpgrade = disableUpgrade;
        
        _upgradeAttempts = 3;
        _disableAutoCancel = NO;
    }
    return self;
}


#pragma mark - PA2GroupedTask

- (void) onTaskStart
{
    [super onTaskStart];
    [self fetchActivationStatusAndTestUpgrade];
}

- (void) onTaskRestart
{
    [super onTaskRestart];
    _upgradeAttempts = 3;
    _disableAutoCancel = NO;
    _receivedStatus = nil;
}

- (void) onTaskCompleteWithResult:(PowerAuthActivationStatus*)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getActivationStatusTask:self didFinishedWithStatus:result error:error];
}

- (BOOL) shouldCancelWhenNoChildOperationIsSet
{
    return _disableAutoCancel == NO;
}

#pragma mark - Activation status fetcher

/**
 Performs getting status from the server and starts protocol upgrade, if possible.
 */
- (void) fetchActivationStatusAndTestUpgrade
{
    [self fetchActivationStatus:^(PowerAuthActivationStatus *status, NSError *error) {
        // We have status. Test for protocol upgrade.
        if (status.isProtocolUpgradeAvailable || _sessionProvider.hasPendingProtocolUpgrade) {
            if (!_disableUpgrade) {
                // If protocol upgrade is available, then simply switch to upgrade code.
                [self continueUpgradeWith:status];
                return;
            }
            PowerAuthLog(@"WARNING: GetStatus: Upgrade to newer protocol version is disabled.");
        }
        // Now test whether the counter should be synchronized on the server.
        if (status.isSignatureCalculationRecommended) {
            [self synchronizeCounterWith:status];
            return;
        }
        // Otherwise return the result as usual.
        [self complete:status error:error];
    }];
}


/**
 Fetch activation status from the server. This is the low level operation, which simply
 receives the status from the server and does no additional processing.
 */
- (void) fetchActivationStatus:(void(^)(PowerAuthActivationStatus *status, NSError *error))callback
{
    // Perform the server request
    PA2GetActivationStatusRequest * request = [[PA2GetActivationStatusRequest alloc] init];
    request.activationId = _sessionProvider.activationIdentifier;
    request.challenge    = [PowerAuthCoreSession generateActivationStatusChallenge];
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint getActivationStatus];
    //
    id<PowerAuthOperationTask> fetchStatusTask = [_client postObject:request to:endpoint completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
        // HTTP request completion
        PowerAuthActivationStatus * statusObject = nil;
        // Validate result
        if (status == PowerAuthRestApiResponseStatus_OK) {
            // Cast to response object
            PA2GetActivationStatusResponse * ro = response;
            // Prepare unlocking key (possession factor only)
            PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
            keys.possessionUnlockKey = _deviceRelatedKey;
            // Try to decode the activation status
            PowerAuthCoreEncryptedActivationStatus * encryptedStatus = [[PowerAuthCoreEncryptedActivationStatus alloc] init];
            encryptedStatus.challenge               = request.challenge;
            encryptedStatus.encryptedStatusBlob = ro.encryptedStatusBlob;
            encryptedStatus.nonce                   = ro.nonce;
            PowerAuthCoreActivationStatus * coreStatusObject = [_sessionProvider writeTaskWithSession:^id (PowerAuthCoreSession * session) {
                return [session decodeActivationStatus:encryptedStatus keys:keys];
            }];
            if (coreStatusObject) {
                statusObject = [[PowerAuthActivationStatus alloc] initWithCoreStatus: coreStatusObject customObject:ro.customObject];
            } else {
                error = PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil);
            }
        }
        // Execute callback
        callback(statusObject, error);
    }];
    [self replaceCancelableOperation:fetchStatusTask];
}

#pragma mark - Counter synchronization

/**
 Continue task with signature counter synchronization. In this case, just '/pa/signature/validate' endpoint is called,
 with simple possession-only signature. That will force server to catch up with the local counter.
 */
- (void) synchronizeCounterWith:(PowerAuthActivationStatus*)status
{
    PowerAuthLog(@"GetStatus: Trying synchronize counter with server.");
    //
    PA2ValidateSignatureRequest * request = [PA2ValidateSignatureRequest requestWithReason:@"COUNTER_SYNCHRONIZATION"];
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint validateSignature];
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possession];
    //
    id<PowerAuthOperationTask> validateTask = [_client postObject:request to:endpoint auth:auth completion:^(PowerAuthRestApiResponseStatus apiStatus, id<PA2Decodable> response, NSError *error) {
        if (!error) {
            [self complete:status error:nil];
        } else {
            [self complete:nil error:error];
        }
    }];
    [self replaceCancelableOperation:validateTask];
}

#pragma mark - Protocol upgrade

/**
 Continue task with the protocol upgrade. This is the "main" function, which handles all possible
 combination of upgrade states, so it's safe to call it when the status is known.
 */
- (void) continueUpgradeWith:(PowerAuthActivationStatus*)status
{
    // Keep status objects for delayed processing.
    _receivedStatus = status;
    
    // Check whether we reached maximum attempts for upgrade
    if (_upgradeAttempts-- > 0) {
        [self continueUpgradeToV3:status];
    } else {
        NSError * error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Number of upgrade attemps reached its maximum.");
        [self complete:nil error:error];
    }
}

/**
 Continue task with the protocol V3 upgrade.
 */
- (void) continueUpgradeToV3:(PowerAuthActivationStatus*)status
{
    PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* (PowerAuthCoreSession * session) {
        PowerAuthCoreProtocolVersion serverVersion = status.currentActivationVersion;
        PowerAuthCoreProtocolVersion localVersion = session.protocolVersion;

        if (serverVersion == PowerAuthCoreProtocolVersion_V2) {
            
            // Server is still on V2 version, so we need to determine how to continue.
            // At first, we should check whether the upgrade was started, because this
            // continue method must handle all possible upgrade states.
            
            if (session.pendingProtocolUpgradeVersion == PowerAuthCoreProtocolVersion_NA) {
                // Upgrade has not been started yet.
                PowerAuthLog(@"GetStatus: Starting upgrade to protocol V3.");
                if (NO == [session startProtocolUpgrade]) {
                    return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Failed to start protocol upgrade.")];
                }
            }
            
            // Now lets test current local protocol version
            if (localVersion == PowerAuthCoreProtocolVersion_V2) {
                // Looks like we didn't start upgrade on the server, or the request
                // didn't finish. In other words, we still don't have the CTR_DATA locally.
                [self startUpgradeToV3];
                return nil;
                
            } else if (localVersion == PowerAuthCoreProtocolVersion_V3) {
                // We already have CTR_DATA, but looks like server didn't receive our "commit" message.
                // This is because server's version is still in V2.
                [self commitUpgradeToV3];
                return nil;
            }
            
            // Current local version is unknown. This should never happen, unless there's
            // a new protocol version and upgrade routine is not updated.
            // This branch will report "Internal protocol upgrade error"
            
        } else if (serverVersion == PowerAuthCoreProtocolVersion_V3) {
            
            // Server is already on V3 version, check the local version
            if (localVersion == PowerAuthCoreProtocolVersion_V2) {
                // This makes no sense. Server is in V3, but the client is still in V2.
                return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Server-Client protocol version mishmash.")];
                
            } else if (localVersion == PowerAuthCoreProtocolVersion_V3) {
                // Server is in V3, local version is in V3
                PowerAuthCoreProtocolVersion pendingUpgradeVersion = session.pendingProtocolUpgradeVersion;
                if (pendingUpgradeVersion == PowerAuthCoreProtocolVersion_V3) {
                    // Looks like we need to just finish the upgrade. Server and our local session
                    // are already on V3, but pending flag indicates, that we're still in upgrade.
                    [self finishUpgradeToV3];
                    return nil;
                    
                } else if (pendingUpgradeVersion == PowerAuthCoreProtocolVersion_NA) {
                    // Server's in V3, client's in V3, no pending upgrade.
                    // This is weird, but we can just report the result.
                    return [PA2Result success:_receivedStatus];
                }
            }
            
            // Current local version is unknown. This should never happen, unless there's
            // a new protocol version and upgrade routine is not updated.
            // This branch will also report "Internal protocol upgrade error"
            
        } else {
            // Server's version is unknown.
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Unknown server version.")];
        }
        // Otherwise report an upgrade error.
        return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Internal protocol upgrade error.")];
    }];
    [self completeWithResult:result];
}

/**
 Starts upgrade to V3 on the server.
 */
- (void) startUpgradeToV3
{
    // Disable auto cancel
    _disableAutoCancel = YES;
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint upgradeStartV3];
    //
    id<PowerAuthOperationTask> startUpgradeTask = [_client postObject:nil to:endpoint completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
        PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* (PowerAuthCoreSession * session) {
            // Response from start upgrade request
            if (status == PowerAuthRestApiResponseStatus_OK) {
                PA2UpgradeStartV3Response * ro = response;
                PowerAuthCoreProtocolUpgradeDataV3 * v3data = [[PowerAuthCoreProtocolUpgradeDataV3 alloc] init];
                v3data.ctrData = ro.ctrData;
                if ([session applyProtocolUpgradeData:v3data]) {
                    // Everything looks fine, we can continue with commit on server.
                    // Since this change, we can sign requests with V3 signatures
                    // and local protocol version is bumped to V3.
                    [self commitUpgradeToV3];
                    
                } else {
                    // The PowerAuthCoreSession did reject our upgrade data.
                    return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Failed to apply protocol upgrade data.")];
                }
            } else {
                // Upgrade start failed. This might be a temporary problem with the network,
                // so try to repeat everything.
                [self fetchActivationStatusAndTestUpgrade];
            }
            return nil;
        }];
        [self completeWithResult:result];
    }];
    [self replaceCancelableOperation:startUpgradeTask];
}

/**
 Commits upgrade to V3 on the server.
 */
- (void) commitUpgradeToV3
{
    // Disable auto cancel
    _disableAutoCancel = YES;
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint upgradeCommitV3];
    PowerAuthAuthentication * auth = [PowerAuthAuthentication possession];
    //
    id<PowerAuthOperationTask> commitUpgradeTask = [_client postObject:nil to:endpoint auth:auth completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
        // HTTP request completion
        if (status == PowerAuthRestApiResponseStatus_OK) {
            // Everything looks fine, just finish the upgrade.
            [self finishUpgradeToV3];
        } else {
            // Upgrade start failed. This might be a temporary problem with the network,
            // so try to repeat everything.
            [self fetchActivationStatusAndTestUpgrade];
        }
    }];
    [self replaceCancelableOperation:commitUpgradeTask];
}

/**
 Completes the whole upgrade process locally.
 */
- (void) finishUpgradeToV3
{
    PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* (PowerAuthCoreSession * session) {
        if ([session finishProtocolUpgrade]) {
            PowerAuthLog(@"Upgrade: Activation was successfully upgraded to protocol V3.");
            // Everything looks fine, we can report previously cached status
            return [PA2Result success:_receivedStatus];
        } else {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Failed to finish protocol upgrade process.")];
        }
    }];
    [self completeWithResult:result];
}

/**
 Complete task with PA2Result object. If result is not available, then the task is not finished yet.
 */
- (void) completeWithResult:(PA2Result<PowerAuthActivationStatus*>*)result
{
    if (result) {
        [self complete:result.result error:result.error];
    }
}

@end

