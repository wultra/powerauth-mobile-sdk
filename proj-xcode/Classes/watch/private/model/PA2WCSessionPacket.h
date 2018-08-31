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

#import "PA2WCSessionPacket_Constants.h"


/**
 The PA2WCSessionPacketData protocol defines payload transmitted in
 PA2WCSessionPacket.
 */
@protocol PA2WCSessionPacketData <NSObject>

/**
 Implementation must deserialize object from provided dictionary.
 */
- (id) initWithDictionary:(NSDictionary*)dictionary;
/**
 Implementation must serialize object to provided mutable dictionary.
 */
- (void) serializeToDictionary:(NSMutableDictionary*)dictionary;
/**
 Implementation must return YES if data in the payload is valid.
 */
- (BOOL) validatePacketData;

@end


/**
 The PA2WCSessionPacket class defining data packet transmitted between iPhone and Apple Watch.
 The object is used for both directions, for reply and response data.
 */
@interface PA2WCSessionPacket : NSObject

/**
 Contains error in case that error has to be transmitted or has been received.
 */
@property (nonatomic, strong) NSError * error;
/**
 Contains target identifier. The identifier is typically composed from two parts:
 
 1) domain identifier, defining service which has to handle the packet.
 2) instance identifier, addressing an exact object instance (see PowerAuthConfiguration.instanceId)
 
 You can use PA2WCSessionPacket_RESPONSE_TARGET constant for reply packets.
 */
@property (nonatomic, strong) NSString * target;

/**
 After deserialization, property contains a source dictionary.
 */
@property (nonatomic, strong, readonly) NSDictionary * sourceData;

/**
 Before serialization, you can store instnace of `PA2WCSessionPacketData` which will be properly serialized.
 After deserialization, the property is nil. You have to deserialize content afterwards
 with using content from sourceData.
 */
@property (nonatomic, strong) id<PA2WCSessionPacketData> payload;

// Not serialized properties

/**
 Contains YES, only if this is a request packet, but response handler is not available.
 This gives data handler opportunity to send response internally, if it is required.
 */
@property (nonatomic, assign) BOOL requestWithoutReplyHandler;

/**
 Contains YES for response packets, when the response may be send to counterpart
 as lazy transmission (without completion)
 */
@property (nonatomic, assign) BOOL sendLazyResponseIfPossible;

// Easy accessors

/**
 Returns response packet with error.
 */
+ (PA2WCSessionPacket*) packetWithError:(NSError*)error;
/**
 Returns response packet with generic success object in the payload.
 */
+ (PA2WCSessionPacket*) packetWithSuccess;
/**
 Returns response packet with success object containing specific reply code in the payload.
 */
+ (PA2WCSessionPacket*) packetWithSuccessCode:(NSInteger)code;
/**
 Returns packet with embedded payload, for given target.
 */
+ (PA2WCSessionPacket*) packetWithData:(id<PA2WCSessionPacketData>)data target:(NSString*)target;

// Serialization

/**
 Returns content of packet serialized to the dictionary.
 */
- (NSDictionary*) toDictionary;
/**
 Initializes packet with content of the dictionary.
 */
- (id) initWithDictionary:(NSDictionary*)dictionary;

@end
