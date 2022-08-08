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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthToken.h>

#import "PowerAuthAuthentication+Private.h"
#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateRemoteTokenProvider.h"
#import "PA2GroupedTask.h"

/**
 The PA2CreateTokenTask groups multiple create token requests into one operation
 executed on remote token provider.
 */
@interface PA2CreateTokenTask : PA2GroupedTask<PowerAuthToken*>

/**
 Initialize object with required parameters.
 
 @param provider Class that implement getting a token from remote location.
 @param tokenStore Token store implementation.
 @param authentication Authentication required for creating the token.
 @param activationId Activation identifier.
 @param tokenName Token name.
 @param sharedLock Shared recursive lock.
 */
- (id) initWithProvider:(id<PA2PrivateRemoteTokenProvider>)provider
             tokenStore:(id<PowerAuthPrivateTokenStore>)tokenStore
         authentication:(PowerAuthAuthentication*)authentication
           activationId:(NSString*)activationId
              tokenName:(NSString*)tokenName
             sharedLock:(id<NSLocking>)sharedLock;

/**
 Contains name of token to be created.
 */
@property (nonatomic, readonly, strong) NSString * tokenName;
/**
 Contains assigned authentication object.
 */
@property (nonatomic, readonly, strong) PowerAuthAuthentication * authentication;

@end
