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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private

#import "PowerAuthMacros.h"
// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#import "PA2WCSessionPacket.h"

@class PowerAuthWCSessionManager;

/// The `PA2WCSessionDataHandlerResponse` class contains packet for response
/// produced in `PA2WCSessionDataHandler` implementation.
@interface PA2WCSessionDataHandlerResponse : NSObject

/// Contains `YES` if this response is asynchronous due to a delayed completion.
@property (nonatomic, readonly) BOOL delayedCompletion;

/// Contains response packet or `nil` if response is not available yet.
@property (nonatomic, readonly, strong, nullable) PA2WCSessionPacket * responsePacket;

/// Create instance of response object for asynchronous reply. The response
/// packet will be provided later, after the asynchronous operation is finished.
+ (nonnull instancetype) asyncResponse;

/// Create instance of response object with the response packet.
/// - Parameter responsePacket: Packet for response.
+ (nonnull instancetype) responseWithPacket:(nonnull PA2WCSessionPacket*)responsePacket;

/// Create instance of response object with the error.
/// - Parameter error: Error to send as response.
+ (nonnull instancetype) responseWithError:(nonnull NSError*)error;

/// Create instance of response object with the error message. The error code
/// is set to `PowerAuthErrorCode_WatchConnectivity`.
/// - Parameter errorMessage: Error message to send as response.
+ (nonnull instancetype) responseWithErrorMessage:(nonnull NSString*)errorMessage;

/// Set completion callback for asynchronous reply. The callback is called immediately
/// when the response is completed with packet or with error.
/// - Parameter completionCallback: Completion callback.
- (void) setCompletionCallback:(void(^_Nonnull)(PA2WCSessionPacket * _Nonnull response))completionCallback;

/// Complete asynchronous response with response packet.
/// - Parameter responsePacket: Response packet to use for reply.
- (void) completeWithResponsePacket:(nonnull PA2WCSessionPacket*)responsePacket;

/// Complete asynchronous response with error.
/// - Parameter error: Error to use for reply.
- (void) completeWithError:(nonnull NSError*)error;

@end

/**
 The PA2WCSessionDataHandler protocol defines interface for processing packets
 transmitted between Apple Watch and iPhone.
 */
@protocol PA2WCSessionDataHandler <NSObject>
@required

/**
 Implementation must return YES, if packet can be processed in this handler.
 */
- (BOOL) canProcessPacket:(nonnull PA2WCSessionPacket*)packet;

/**
 Implementation must always return response for given packet. The PA2WCSessionManager is calling
 this method only for handler which can process the packet (e.g. canProcessPacket was called before
 and method returned YES)
 */
- (nonnull PA2WCSessionDataHandlerResponse*) sessionManager:(nonnull PowerAuthWCSessionManager*)manager responseForPacket:(nonnull PA2WCSessionPacket*)packet;

@end

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
