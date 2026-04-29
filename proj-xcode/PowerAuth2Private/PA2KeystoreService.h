/*
 * Copyright 2024 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthOperationTask.h>
#import "PA2SessionInterface.h"

@class PA2GetTemporaryKeyTask, PA2CoreHttpClient;

/// The `PA2GetTemporaryKeyTaskDelegate` protocol allows class that create `PA2GetTemporaryKeyTask` object
/// monitor the task completion.
@protocol PA2GetTemporaryKeyTaskDelegate <NSObject>
@required
/// Called when the get activation task complete its execution.
- (void) getTemporaryKeyTask:(nonnull PA2GetTemporaryKeyTask*)task
          didFinishWithError:(nullable NSError*)error;
@end


/// The `PA2KeystoreService` manages temporary encryption keys for PowerAuthSDK instance.
@interface PA2KeystoreService : NSObject<PA2GetTemporaryKeyTaskDelegate>

- (nonnull instancetype) initWithHttpClient:(nonnull PA2CoreHttpClient*)httpClient
                           sessionInterface:(nonnull id<PA2SessionInterface>)sessionInterface
                                 sharedLock:(nonnull id<NSLocking>)sharedLock;
/**
 Determine whether instance of this service contains a temporary encryption key for the requested encryption scope.
 */
- (BOOL) hasKeyForEncryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope;

/**
 Create a temporary encryption key for the requested scope. If such key already exists and is still valid, then function does nothing
 and returns nil. If the key is not available, or is already expired, then the function returns asynchronous task with an underlying
 HTTP request.
 */
- (nullable id<PowerAuthOperationTask>) createKeyForEncryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope
                                                          callback:(nonnull void(^)(NSError * _Nullable error))callback
                                                     callbackQueue:(dispatch_queue_t _Nullable)callbackQueue;

@end
