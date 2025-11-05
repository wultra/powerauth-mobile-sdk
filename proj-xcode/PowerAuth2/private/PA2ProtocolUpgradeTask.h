/**
 * Copyright 2025 Wultra s.r.o.
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
#import "PA2GroupedTask.h"

@class PA2CoreHttpClient;
@class PA2ProtocolUpgradeTask;
@class PowerAuthCoreData;
@class PowerAuthCorePassword;

/**
 The `PA2ProtocolUpgradeTaskDelegate` protocol allows adding
 an action on `PA2ProtocolUpgradeTask` completition.
 */
@protocol PA2ProtocolUpgradeTaskDelegate <NSObject>
@required

/**
 Called when the protocol upgrade task completes its execution. It cleans the resources
 used for the upgrade protocol task and updates the biometry KEK, if the task finished
 without any error and the biometry KEK is passed.
 */
- (void) startProtocolUpgradeTask:(PA2ProtocolUpgradeTask*)task
             didFinishedWithError:(NSError*)error
            newBiometryKekToStore:(PowerAuthCoreData*)newBiometryKek;

@end

/**
 The `PA2ProtocolUpgradeTask` class implements protocol upgrade procedure.
 */
@interface PA2ProtocolUpgradeTask : PA2GroupedTask<id>

/**
 Initializes the `PA2ProtocolUpgradeTask`.
 
 @param httpClient HTTP client for communicating with the server.
 @param sessionProvider PowerAuthCoreSession provider.
 @param delegate Delegate to be called once the task is finished.
 @param sharedLock Shared lock with recursive locking capability.
 @param password Password used for protocol upgrade start authentication. Must be set to allow protocol upgrade start.
 @param newBiometryKek A new biometry kek for the upgraded protocol. Must be passed if biometry factor is currently set.
 */
- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
                 password:(PowerAuthCorePassword*)password
           newBiometryKek:(PowerAuthCoreData*)newBiometryKek;

/**
 Initializes the `PA2ProtocolUpgradeTask` with password, but without biometry KEK.
 Meaning the task is able to start the protocol upgrade iff biometry factor is not set currently.
 
 @param httpClient HTTP client for communicating with the server.
 @param sessionProvider PowerAuthCoreSession provider.
 @param delegate Delegate to be called once the task is finished.
 @param sharedLock Shared lock with recursive locking capability.
 @param password Password used for protocol upgrade start authentication.
 */
- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
                 password:(PowerAuthCorePassword*)password;

/**
 Initializes the `PA2ProtocolUpgradeTask` without password and biometry KEK,
 which means the created instance can be used only for the protocol upgrade confirm.
 
 @param httpClient HTTP client for communicating with the server.
 @param sessionProvider PowerAuthCoreSession provider.
 @param delegate Delegate to be called once the task is finished.
 @param sharedLock Shared lock with recursive locking capability.
 */
- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock;

@end
