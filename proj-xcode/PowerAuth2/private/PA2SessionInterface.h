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

/**
 The `PA2SessionInterface` extends public `PowerAuthCoreSessionProvider` with private API
 not exposed to the application.
 */
@protocol PA2SessionInterface <PowerAuthCoreSessionProvider, PA2TokenDataLock>
@required

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
- (nullable NSError*) startExternalPendingOperation:(PowerAuthExternalPendingOperationType)externalPendingOperation;


/**
 Add operation to the queue synchronized between multiple applications.
 */
- (void) addOperation:(nonnull NSOperation*)operation toSharedQueue:(nonnull NSOperationQueue*)queue;

@end
