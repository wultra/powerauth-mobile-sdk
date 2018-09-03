/**
 * Copyright 2017 Wultra s.r.o.
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

#import "PowerAuthToken.h"
#import "PA2PrivateTokenData.h"

@class PowerAuthConfiguration;

/**
 The `PA2PrivateRemoteTokenProvider` protocol defines an interface for getting token from remote location.
 The PowerAuth SDK contains various specific implementations for this interface, for example, one specific
 implementation is managing tokens on the remote server.
 */
@protocol PA2PrivateRemoteTokenProvider <NSObject>

/**
 Implementation may return YES, if `PowerAuthAuthentication` object is required for getting remote token.
 */
- (BOOL) authenticationIsRequired;

/**
 Called once per instance, before request or remove methods are called. So, the implementation can safely put
 a lazy initialization code to this method.
 */
- (void) prepareInstanceForConfiguration:(nonnull PowerAuthConfiguration*)configuration;

/**
 The implementation must create a new access token with given name for requested signature factors.
 The created token objects always contains a valid token data.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens in case of error.
 */
- (nullable PowerAuthTokenStoreTask) requestTokenWithName:(nonnull NSString*)name
										   authentication:(nullable PowerAuthAuthentication*)authentication
											   completion:(nonnull void(^)(PA2PrivateTokenData * _Nullable tokenData, NSError * _Nullable error))completion;

/**
 Removes previously created access token from the remote location.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens in case of error.
 */
- (nullable PowerAuthTokenStoreTask) removeTokenData:(nonnull PA2PrivateTokenData*)tokenData
											  completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion;

/**
 Cancels previously created store task. Note that cancelling may lead to inconsistent state,
 when the server will execute the operation but client application will not get the result.
 
 It is safe to call this method with nil task.
 */
- (void) cancelTask:(nullable PowerAuthTokenStoreTask)task;

@end
