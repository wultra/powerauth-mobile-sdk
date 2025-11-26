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

#import <PowerAuth2/PowerAuthSessionStatusProvider.h>
#import <PowerAuth2/PowerAuthExternalPendingOperation.h>

@class PowerAuthCoreSession;

typedef id _Nullable (^PowerAuthCoreSessionTaskBlock)(PowerAuthCoreSession* _Nonnull session, NSError*_Nonnull*_Nullable error);
typedef BOOL (^PowerAuthCoreSessionTaskBoolBlock)(PowerAuthCoreSession* _Nonnull session, NSError*_Nonnull*_Nullable error);

/**
 The `PowerAuthCoreSessionProvider` extends `PowerAuthSessionStatusProvider` protocol with
 functionality that allows inter-process safe access to the activation. Since SDK version 1.7.x,
 you should never use `PowerAuthCoreSession` directly, without acquiring the lock.
 */
@protocol PowerAuthCoreSessionProvider <PowerAuthSessionStatusProvider>
@required
/**
 Contains activation identifier or nil if there's no activation in the session.
 */
@property (nonatomic, strong, nullable, readonly) NSString * activationIdentifier;

/**
 Resets session into its initial state.
 */
- (BOOL) resetSession:(NSError*_Nullable*_Nullable)error;

/**
 Execute task that suppose to access read-only functions from `PowerAuthCoreSession`. It's allowed to call other
 "read*" or "write*" task functions from the taskBlock.
 
 @param taskBlock Block to execute with properly locked `PowerAuthCoreSession`.
 @return Object returned from the task block.
 */
- (nullable id) readTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBlock)taskBlock
                              error:(NSError*_Nullable*_Nullable)error;

/**
 Execute task that can access read and write functions from `PowerAuthCoreSession`. It's allowed to call other
 "read*" or "write*" task functions from the taskBlock.
 
 @param taskBlock Block to execute with properly locked `PowerAuthCoreSession`.
 @return Object returned from the task block.
 */
- (nullable id) writeTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBlock)taskBlock
                               error:(NSError*_Nullable*_Nullable)error;

/**
 Execute task that suppose to access read-only functions from `PowerAuthCoreSession`. It's allowed to call other
 "read*" or "write*" task functions from the taskBlock.
 
 @param taskBlock Block to execute with properly locked `PowerAuthCoreSession`.
 @return Boolean value returned from the task block.
 */
- (BOOL) readBoolTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBoolBlock)taskBlock
                           error:(NSError*_Nullable*_Nullable)error;

/**
 Execute task that can access read and write functions from `PowerAuthCoreSession`. It's allowed to call other
 "read*" or "write*" task functions from the taskBlock.
 
 @param taskBlock Block to execute with properly locked `PowerAuthCoreSession`.
 @return Boolean value returned from the task block.
 */
- (BOOL) writeBoolTaskWithSession:(nonnull NS_NOESCAPE PowerAuthCoreSessionTaskBoolBlock)taskBlock
                            error:(NSError*_Nullable*_Nullable)error;

/**
 Execute block when no read or write task is open in the current thread. If this thread is in the middle
 of session provider's task, then defer the block execution into the provided queue. It's guaranteed that block
 is always executed when the session provider's local lock is acquired.
 
 @param block Block to execute outside of read or write task.
 @param queue Dispatch queue to use to run the block when the current thread is in the middle of session provider's task.
 */
- (void) executeOutsideOfTask:(void (^ _Nonnull)(void))block
                        queue:(dispatch_queue_t _Nonnull)queue;

@end
