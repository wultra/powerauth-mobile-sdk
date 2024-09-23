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

#import "PA2GroupedTask.h"

@import PowerAuthCore;

@class PA2HttpClient, PA2GetTemporaryKeyTask, PA2GetTemporaryKeyResponse;
@protocol PowerAuthCoreSessionProvider;

/// The `PA2GetTemporaryKeyTaskDelegate` protocol allows class that create `PA2GetTemporaryKeyTask` object
/// monitor the task completion.
@protocol PA2GetTemporaryKeyTaskDelegate <NSObject>
@required
/// Called when the get activation task complete its execution.
- (void) getTemporaryKeyTask:(nonnull PA2GetTemporaryKeyTask*)task 
       didFinishWithResponse:(nullable PA2GetTemporaryKeyResponse*)response
                       error:(nullable NSError*)error;
@end

/// The `PA2GetTemporaryKeyTask` implements grouped task that gets temporary encryption key from the server.
@interface PA2GetTemporaryKeyTask : PA2GroupedTask<PA2GetTemporaryKeyResponse*>

@property (nonatomic, readonly) PowerAuthCoreEciesEncryptorScope encryptorScope;
@property (nonatomic, strong, nullable, readonly) NSString * applicationKey;

- (nonnull instancetype) initWithHttpClient:(nonnull PA2HttpClient*)httpClient
                            sessionProvider:(nonnull id<PowerAuthCoreSessionProvider>)sessionProvider
                                 sharedLock:(nonnull id<NSLocking>)sharedLock
                             applicationKey:(nonnull NSString*)applicationKey
                           deviceRelatedKey:(nullable NSData*)deviceRelatedKey
                             encryptorScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope
                                   delegate:(nonnull id<PA2GetTemporaryKeyTaskDelegate>)delegate;

@end
