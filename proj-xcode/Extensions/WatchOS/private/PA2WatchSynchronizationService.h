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

@interface PA2WatchSynchronizationService : NSObject<PA2WCSessionDataHandler>

@property (class, nonnull, readonly) PA2WatchSynchronizationService * sharedInstance;

- (nullable NSString*) activationIdForSessionInstanceId:(nonnull NSString*)sessionInstanceId;

- (void) updateActivationId:(nullable NSString*)activationId forSessionInstanceId:(nonnull NSString*)sessionInstanceId;

@end
