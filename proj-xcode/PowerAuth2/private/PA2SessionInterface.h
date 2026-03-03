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

#import <PowerAuth2/PowerAuthCoreSessionProvider.h>
#import "PA2SessionDataProvider.h"
#import "PA2TokenDataLock.h"

@import PowerAuthCore;

@class PA2KeystoreService, PA2TimeSynchronizationService;

/**
 The `PA2SessionInterface` extends public `PowerAuthCoreSessionProvider` with private API
 not exposed to the application.
 */
@protocol PA2SessionInterface <PowerAuthCoreSessionProvider, PowerAuthCoreSessionDelegate, PA2TokenDataLock>
@required

/// Load initial session state and optionally clear unsupported data.
///
/// @param clearUnsupportedData If YES, then unsupported data will be erased.
/// @param error Pointer where error is set in case of failure.
- (BOOL) loadInitialState:(BOOL)clearUnsupportedData
                    error:(NSError*_Nullable*_Nullable)error;

/**
 Contains instance to `PowerAuthExternalPendingOperation` in case that other application is doing the critical
 operation right now.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthExternalPendingOperation* externalPendingOperation;

/**
 Notify other applications that the current application is going to start the critical operation, such as protocol upgrade, or activation start.
 @param externalPendingOperation Operation type to start.
 @return NSError in case that other application is already started its own critical operation.
 */
- (BOOL) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation error:(NSError*_Nullable*_Nullable)error;

/**
 Add operation to the queue synchronized between multiple applications.
 */
- (void) addOperation:(nonnull NSOperation*)operation toSharedQueue:(nonnull NSOperationQueue*)queue;

// Services

/// Method stores instances of keystore and time synchronization services in the instance of session interface. The services
/// are used in other parts of SDK for required tasks.
///
/// @param keystoreService Keystore service.
/// @param timeService Time synchronization service.
- (void) connectWithKeystoreService:(nonnull PA2KeystoreService*)keystoreService
                        timeService:(nonnull PA2TimeSynchronizationService*)timeService;

/// Contains instance of PA2KeystoreService. If no service is set, then throws ObjC exception.
@property (nonatomic, strong, nonnull, readonly) PA2KeystoreService* keystoreService;

/// Contains instance of PA2TimeSynchronizationService. If no service is set, then throws ObjC exception.
@property (nonatomic, strong, nonnull, readonly) PA2TimeSynchronizationService* timeSynchronizationService;

@end
