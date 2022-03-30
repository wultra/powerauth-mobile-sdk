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

#pragma mark - Private child task interface

@interface PA2GetActivationStatusChildTask (Private)
/**
 Parent task which manages this object.
 */
@property (nonatomic, weak) PA2GetActivationStatusTask * parentTask;
/**
 Completes child's task execution.

 @param status status received from server, or nil in case of error
 @param customObject optional custom object received from the server
 @param error valid in case of error
 */
- (void) completeWithStatus:(PowerAuthActivationStatus*)status customObject:(NSDictionary*)customObject error:(NSError*)error;

@end


#pragma mark - Status fetching task

@implementation PA2GetActivationStatusTask
{
	id<NSLocking> _lock;
	
	NSData * _deviceRelatedKey;
	id<PowerAuthCoreSessionProvider> _sessionProvider;
	PA2HttpClient * _client;
	void(^_completion)(PA2GetActivationStatusTask*, PowerAuthActivationStatus*, NSDictionary*, NSError*);
	
	__weak NSOperation * _currentOperation;
	NSMutableArray<PA2GetActivationStatusChildTask*>* _childOperations;
	
	BOOL _isCancelled;
	BOOL _exiting;
	
	// Upgrade attempts
	NSInteger _upgradeAttempts;
}

- (id) initWithHttpClient:(PA2HttpClient*)httpClient
		 deviceRelatedKey:(NSData*)deviceRelatedKey
		  sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
			   completion:(void(^)(PA2GetActivationStatusTask*, PowerAuthActivationStatus*, NSDictionary*, NSError*))completion
{
	self = [super init];
	if (self) {
		_lock = [[NSRecursiveLock alloc] init];
		_deviceRelatedKey = deviceRelatedKey;
		_sessionProvider = sessionProvider;
		_client = httpClient;
		_childOperations = [NSMutableArray array];
		_completion = completion;
		_upgradeAttempts = 3;
	}
	return self;
}


#pragma mark - Execution

- (void) execute
{
	[self fetchActivationStatusAndTestUpgrade];
}


/**
 Performs getting status from the server and starts protocol upgrade, if possible.
 */
- (void) fetchActivationStatusAndTestUpgrade
{
	[self fetchActivationStatus:^(PowerAuthActivationStatus *status, NSDictionary *customObject, NSError *error) {
		// We have status. Test for protocol upgrade.
		if (status.isProtocolUpgradeAvailable || _sessionProvider.hasPendingProtocolUpgrade) {
			if (!_disableUpgrade) {
				// If protocol upgrade is available, then simply switch to upgrade code.
				[self continueUpgradeWith:status customObject:customObject];
				return;
			}
			PowerAuthLog(@"WARNING: Upgrade to newer protocol version is disabled.");
		}
		// Now test whether the counter should be synchronized on the server.
		if (status.isSignatureCalculationRecommended) {
			[self synchronizeCounterWith:status customObject:customObject];
			return;
		}
		// Otherwise return the result as usual.
		[self reportCompletionWithStatus:status customObject:customObject error:error];
	}];
}


/**
 Fetch activation status from the server. This is the low level operation, which simply
 receives the status from the server and does no additional processing.
 */
- (void) fetchActivationStatus:(void(^)(PowerAuthActivationStatus *status, NSDictionary *customObject, NSError *error))callback
{
	// Perform the server request
	PA2GetActivationStatusRequest * request = [[PA2GetActivationStatusRequest alloc] init];
	request.activationId = _sessionProvider.activationIdentifier;
	request.challenge    = [PowerAuthCoreSession generateActivationStatusChallenge];
	//
	_currentOperation = [_client postObject:request
										 to:[PA2RestApiEndpoint getActivationStatus]
								 completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
									 // HTTP request completion
									 PowerAuthActivationStatus * statusObject = nil;
									 NSDictionary * customObject = nil;
									 // Validate result
									 if (status == PowerAuthRestApiResponseStatus_OK) {
										 // Cast to response object
										 PA2GetActivationStatusResponse * ro = response;
										 // Prepare unlocking key (possession factor only)
										 PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
										 keys.possessionUnlockKey = _deviceRelatedKey;
										 // Try to decode the activation status
										 PowerAuthCoreEncryptedActivationStatus * encryptedStatus = [[PowerAuthCoreEncryptedActivationStatus alloc] init];
										 encryptedStatus.challenge				= request.challenge;
										 encryptedStatus.encryptedStatusBlob	= ro.encryptedStatusBlob;
										 encryptedStatus.nonce					= ro.nonce;
										 PowerAuthCoreActivationStatus * coreStatusObject = [_sessionProvider writeTaskWithSession:^id _Nullable(PowerAuthCoreSession * _Nonnull session) {
											 return [session decodeActivationStatus:encryptedStatus keys:keys];
										 }];
										 customObject = ro.customObject;
										 if (coreStatusObject) {
											 statusObject = [[PowerAuthActivationStatus alloc] initWithCoreStatus: coreStatusObject];
										 } else {
											 error = PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil);
										 }
									 }
									 // Call back to the application
									 callback(statusObject, customObject, error);
								 }];
}

#pragma mark - Counter synchronization

/**
 Continue task with signature counter synchronization. In this case, just '/pa/signature/validate' endpoint is called,
 with simple possession-only signature. That will force server to catch up with the local counter.
 */
- (void) synchronizeCounterWith:(PowerAuthActivationStatus*)status customObject:(NSDictionary*)customObject
{
	PowerAuthLog(@"GetStatus: Trying synchronize counter with server.");
	_currentOperation = [_client postObject:[PA2ValidateSignatureRequest requestWithReason:@"COUNTER_SYNCHRONIZATION"]
										 to:[PA2RestApiEndpoint validateSignature]
									   auth:[PowerAuthAuthentication possession]
								 completion:^(PowerAuthRestApiResponseStatus apiStatus, id<PA2Decodable> response, NSError *error) {
									 if (!error) {
										 [self reportCompletionWithStatus:status customObject:customObject error:nil];
									 } else {
										 [self reportCompletionWithStatus:nil customObject:nil error:error];
									 }
								 }];
}

#pragma mark - Protocol upgrade

/**
 Continue task with the protocol upgrade. This is the "main" function, which handles all possible
 combination of upgrade states, so it's safe to call it when the status is known.
 */
- (void) continueUpgradeWith:(PowerAuthActivationStatus*)status customObject:(NSDictionary*)customObject
{
	// Keep status objects for delayed processing.
	_receivedStatus = status;
	_receivedCustomObject = customObject;
	
	// Check whether we reached maximum attempts for upgrade
	if (_upgradeAttempts-- > 0) {
		[self continueUpgradeToV3:status];
	} else {
		NSError * error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Number of upgrade attemps reached its maximum.");
		[self reportCompletionWithStatus:nil customObject:nil error:error];
	}
}

/**
 Continue task with the protocol V3 upgrade.
 */
- (void) continueUpgradeToV3:(PowerAuthActivationStatus*)status
{
	PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* _Nullable(PowerAuthCoreSession * _Nonnull session) {
		PowerAuthCoreProtocolVersion serverVersion = status.currentActivationVersion;
		PowerAuthCoreProtocolVersion localVersion = session.protocolVersion;

		if (serverVersion == PowerAuthCoreProtocolVersion_V2) {
			
			// Server is still on V2 version, so we need to determine how to continue.
			// At first, we should check whether the upgrade was started, because this
			// continue method must handle all possible upgrade states.
			
			if (session.pendingProtocolUpgradeVersion == PowerAuthCoreProtocolVersion_NA) {
				// Upgrade has not been started yet.
				PowerAuthLog(@"Upgrade: Starting upgrade to protocol V3.");
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
					return [PA2Result success:_receivedStatus withData:_receivedCustomObject];
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
	[self reportCompletionWithResult:result];
}

/**
 Starts upgrade to V3 on the server.
 */
- (void) startUpgradeToV3
{
	_currentOperation = [_client postObject:nil
										 to:[PA2RestApiEndpoint upgradeStartV3]
								 completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
									PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* (PowerAuthCoreSession * _Nonnull session) {
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
									[self reportCompletionWithResult:result];
								}];
}

/**
 Commits upgrade to V3 on the server.
 */
- (void) commitUpgradeToV3
{
	_currentOperation = [_client postObject:nil
										 to:[PA2RestApiEndpoint upgradeCommitV3]
									   auth:[PowerAuthAuthentication possession]
								 completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
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
}

/**
 Completes the whole upgrade process locally.
 */
- (void) finishUpgradeToV3
{
	PA2Result<PowerAuthActivationStatus*>* result = [_sessionProvider writeTaskWithSession:^PA2Result<PowerAuthActivationStatus*>* _Nullable(PowerAuthCoreSession * _Nonnull session) {
		if ([session finishProtocolUpgrade]) {
			PowerAuthLog(@"Upgrade: Activation was successfully upgraded to protocol V3.");
			// Everything looks fine, we can report previously cached status
			return [PA2Result success:_receivedStatus withData:_receivedCustomObject];
		} else {
			return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_ProtocolUpgrade, @"Failed to finish protocol upgrade process.")];
		}
	}];
	[self reportCompletionWithResult: result];
}

#pragma mark - PowerAuthOperationTask

- (BOOL) isCancelled
{
	return _isCancelled;
}

- (void) cancel
{
	[_lock lock];
	//
	_isCancelled = YES;
	// Cancel possible pending operation
	[_currentOperation cancel];
	_currentOperation = nil;
	// Normally, this kind of operation is never cancelled, unless the SDK session is resetting its state.
	// If there are some operations waiting for the completion, then we should report an error.
	NSError * error = PA2MakeError(PowerAuthErrorCode_OperationCancelled, nil);
	[self reportCompletionWithStatus:nil customObject:nil error:error];
	//
	[_lock unlock];
}



#pragma mark - Child tasks

- (BOOL) addChildTask:(PA2GetActivationStatusChildTask*)task
{
	BOOL success;
	[_lock lock];
	{
		if (!_exiting) {
			[_childOperations addObject:task];
			task.parentTask = self;
			success = YES;
		} else {
			success = NO;
		}
	}
	[_lock unlock];
	return success;
}

- (void) cancelChildTask:(PA2GetActivationStatusChildTask*)task
{
	[_lock lock];
	{
		[_childOperations removeObject:task];
	}
	[_lock unlock];
}

- (void) reportCompletionWithStatus:(PowerAuthActivationStatus*)status customObject:(NSDictionary*)customObject error:(NSError*)error
{
	BOOL doubleExiting;
	NSArray * childTasks;
	[_lock lock];
	{
		doubleExiting = _exiting;
		childTasks = [_childOperations copy];
		[_childOperations removeAllObjects];
		_exiting = YES;
	}
	[_lock unlock];
	
	if (doubleExiting) {
		// Looks like that we're already exiting. So ignore that call.
		return;
	}
	
	// Call back to PowerAuthSDK, this should be done before we notify application, to update
	// last status & object properties in PowerAuthSDK
	if (_completion) {
		_completion(self, status, customObject, error);
		_completion = nil;
	}
	
	// Complete child tasks with result.
	[childTasks enumerateObjectsUsingBlock:^(PA2GetActivationStatusChildTask * task, NSUInteger idx, BOOL * stop) {
		[task completeWithStatus:status customObject:customObject error:error];
	}];
}

- (void) reportCompletionWithResult:(PA2Result<PowerAuthActivationStatus*>*)result
{
	// Report only when result is available. If not available, then the task is not finished yet.
	if (result) {
		[self reportCompletionWithStatus:result.result customObject:result.associatedData error:result.error];
	}
}

@end




#pragma mark - Child task class -

@implementation PA2GetActivationStatusChildTask
{
	__weak PA2GetActivationStatusTask * _parentTask;
	dispatch_queue_t _completionQueue;
	void(^_completion)(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error);
	BOOL _isCancelled;
}

- (instancetype) initWithCompletionQueue:(dispatch_queue_t)completionQueue
							  completion:(void(^)(PowerAuthActivationStatus * status, NSDictionary * customObject, NSError * error))callback
{
	self = [super init];
	if (self) {
		_completionQueue = completionQueue;
		_completion = callback;
	}
	return self;
}

- (BOOL) isCancelled
{
	return _isCancelled;
}

- (void) cancel
{
	[_parentTask cancelChildTask:self];
	
	dispatch_async(_completionQueue, ^{
		_isCancelled = YES;
		_completion = nil;
	});
}

- (void) setParentTask:(PA2GetActivationStatusTask*)parentTask
{
	_parentTask = parentTask;
}

- (void) completeWithStatus:(PowerAuthActivationStatus*)status customObject:(NSDictionary*)customObject error:(NSError*)error
{
	dispatch_async(_completionQueue, ^{
		if (!_isCancelled) {
			_isCancelled = YES;
			if (_completion) {
				_completion(status, customObject, error);
				_completion = nil;
			}
		}
	});
}

@end
