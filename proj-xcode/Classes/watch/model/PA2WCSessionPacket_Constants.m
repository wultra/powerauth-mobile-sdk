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

#import "PA2WCSessionPacket_Constants.h"

NSString * const PA2WCSessionPacket_USER_INFO_KEY		= @"io.getlime.PowerAuth.PA2WCSessionPacket";

NSString * const PA2WCSessionPacket_RESPONSE_TARGET		= @"*";
NSString * const PA2WCSessionPacket_SESSION_TARGET		= @"session:";
NSString * const PA2WCSessionPacket_TOKEN_TARGET		= @"token:";


NSString * const PA2WCSessionPacket_KEY_TARGET			= @"target";
NSString * const PA2WCSessionPacket_KEY_ERROR_CODE		= @"errorCode";
NSString * const PA2WCSessionPacket_KEY_ERROR_DOM		= @"errorDomain";
NSString * const PA2WCSessionPacket_KEY_ERROR_MSG		= @"errorMsg";

NSString * const PA2WCSessionPacket_KEY_ACTIVATION_CMD	= @"activationCmd";
NSString * const PA2WCSessionPacket_KEY_ACTIVATION_ID	= @"activationId";
NSString * const PA2WCSessionPacket_CMD_SESSION_GET		= @"get_session";
NSString * const PA2WCSessionPacket_CMD_SESSION_PUT		= @"put_session";

NSString * const PA2WCSessionPacket_KEY_TOKEN_CMD		= @"tokenCmd";
NSString * const PA2WCSessionPacket_KEY_TOKEN_NAME		= @"tokenName";
NSString * const PA2WCSessionPacket_KEY_TOKEN_DATA		= @"tokenData";
NSString * const PA2WCSessionPacket_KEY_TOKEN_NA		= @"tokenNotFound";
NSString * const PA2WCSessionPacket_CMD_TOKEN_GET		= @"get_token";
NSString * const PA2WCSessionPacket_CMD_TOKEN_PUT		= @"put_token";
NSString * const PA2WCSessionPacket_CMD_TOKEN_REMOVE	= @"remove_token";

NSString * const PA2WCSessionPacket_KEY_SUCCESS			= @"successCode";
