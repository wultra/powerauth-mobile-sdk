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

#import <PowerAuth2/PowerAuthCoreSessionProvider.h>
#import <PowerAuth2/PowerAuthActivationStatus.h>
#import "PA2GroupedTask.h"

@class PA2HttpClient;
@class PowerAuthCoreSession;
@class PA2GetActivationStatusTask;

/**
 The `PA2GetActivationStatusTaskDelegate` protocol allows class that create PA2GetActivationStatusTask object
 monitor the task completion.
 */
@protocol PA2GetActivationStatusTaskDelegate <NSObject>
@required
/**
 Called when the get activation task complete its execution.
 */
- (void) getActivationStatusTask:(PA2GetActivationStatusTask*)task didFinishedWithStatus:(PowerAuthActivationStatus*)status error:(NSError*)error;

@end

/**
 The `PA2GetActivationStatusTask` class implements getting activation status from the server
 and the protocol upgrade. The upgrade is started automatically, depending on the
 local and server's state of the activation.
 */
@interface PA2GetActivationStatusTask : PA2GroupedTask<PowerAuthActivationStatus*>

/**
 Initializes the object.

 @param httpClient HTTP client for communicating with the server
 @param deviceRelatedKey key for unlocking possession factor
 @param sessionProvider PowerAuthCoreSession provider.
 @param delegate Delegate to be called once the task is finished. The weak reference is used internally.
 @param sharedLock Shared lock with recursive locking capability.
 @param disableUpgrade Set to true whether the protocol upgrade should be disabled.
 @return initialized object
 */
- (id) initWithHttpClient:(PA2HttpClient*)httpClient
		 deviceRelatedKey:(NSData*)deviceRelatedKey
		  sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
				 delegate:(id<PA2GetActivationStatusTaskDelegate>)delegate
			   sharedLock:(id<NSLocking>)sharedLock
		   disableUpgrade:(BOOL)disableUpgrade;

@end
