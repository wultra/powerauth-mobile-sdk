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

#import "PA2WCSessionPacket.h"

/**
 The PA2WCSessionPacket_TokenData object contains information
 about one named token.
 */
@interface PA2WCSessionPacket_TokenData : NSObject<PA2WCSessionPacketData>

/**
 Supported commands:
 	PA2WCSessionPacket_CMD_TOKEN_GET - when watchOS is asking for token from iIOS.
 		- response is PA2WCSessionPacket_CMD_TOKEN_PUT
 	PA2WCSessionPacket_CMD_TOKEN_REMOVE - when IOS wants to remove token from watchOS
 		- response is "Success" packet
 	PA2WCSessionPacket_CMD_TOKEN_PUT - when IOS wants to push token to the watchOS
 		- response is "Success" packet
 */
@property (nonatomic, strong) NSString * command;
/**
 Symbolic name of the token. The value is required in all commands.
 */
@property (nonatomic, strong) NSString * tokenName;
/**
 Required only for PUT command. If PUT command is used and value is nil, then the tokenNotFound
 must be set to YES.
 */
@property (nonatomic, strong) NSData * tokenData;
/**
 Contains YES when PUT command is used as reply and requested token is not available on counterpart.
 */
@property (nonatomic, assign) BOOL tokenNotFound;

@end
