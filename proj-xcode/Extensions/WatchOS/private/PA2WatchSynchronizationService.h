/**
 * Copyright 2018 Lime - HighTech Solutions s.r.o.
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

#import "PA2WCSessionDataHandler.h"

/**
 On watchOS, the PA2WatchSynchronizationService class is responsible for processing
 ALL requests received from the iPhone. Unlike on the iPhone, we're not registering particular
 instances of SDK objects to the PA2WCSessionManager, but using just one service for all purposes.
 
 The reason for this is fact, that both PowerAuthWatchSDK and its internal token store are accessing
 data directly from the keychain and therefore the keychain is the only synchronized storage.
 */
@interface PA2WatchSynchronizationService : NSObject<PA2WCSessionDataHandler>

/**
 Singleton for PA2WatchSynchronizationService class.
 */
@property (class, nonnull, readonly) PA2WatchSynchronizationService * sharedInstance;

/**
 Returns activationId for given session instance identifier. In fact, if the non-nil value is
 returned, then the requested session is still valid.
 */
- (nullable NSString*) activationIdForSessionInstanceId:(nonnull NSString*)sessionInstanceId;

/**
 Removes or adds activation for given session instance identifier, depending on nullability of activationId.
 */
- (void) updateActivationId:(nullable NSString*)activationId forSessionInstanceId:(nonnull NSString*)sessionInstanceId;

@end
