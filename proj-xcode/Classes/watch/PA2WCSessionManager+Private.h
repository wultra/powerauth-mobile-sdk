/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2WCSessionManager.h"
#import "PA2WCSessionDataHandler.h"
#import "PA2WCSessionPacket.h"
#import "PA2Log.h"

@interface PA2WCSessionManager (Private)

#pragma mark - Handler registry

/**
 Registers a new handler to the session manager. The manager is keeping weak reference to the provided
 handler object.
 */
- (void) registerDataHandler:(id<PA2WCSessionDataHandler>)handler;
/**
 Removes previously registered handler from session manager.
 */
- (void) unregisterDataHandler:(id<PA2WCSessionDataHandler>)handler;
/**
 Returns handler which can process given packet or nil if there's no such
 registered handler. If both regular and fallback handler can process packet,
 then the regular packet has higher priorty and is returned in result.
 */
- (id<PA2WCSessionDataHandler>) handlerForPacket:(PA2WCSessionPacket*)packet;

/**
 Registers a new fallback handler to the session manager. The register is keeping
 strong reference to the provided handler and you cannot unregister this kind of handler.
 */
- (void) registerFallbackDataHandler:(id<PA2WCSessionDataHandler>)handler;


#pragma mark - Sending data

/**
 Sends packet without completion block. The WCSession.sendMessageData method is used if the counterpart
 device is reachable, otherwise WCSession.transferUserInfo is used as fallback.
 */
- (void) sendPacket:(PA2WCSessionPacket*)packet;

/**
 Sends packet with completion block. The responseClass parameter defines a class for response's payload
 deserialization. If nil is specified, then the response packet is kept intact.
 The counterpart device must be reachable, otherwise an error is produced.
 */
- (void) sendPacketWithResponse:(PA2WCSessionPacket*)packet
				  responseClass:(Class)responseClass
					 completion:(void(^)(PA2WCSessionPacket * response, NSError * error))completion;

@end
