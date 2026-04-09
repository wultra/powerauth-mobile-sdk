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

#import "PA2WCSessionPacket_Constants.h"

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_USER_INFO_KEY       = @"com.wultra.PowerAuth.PA2WCSessionPacket";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_RESPONSE_TARGET     = @"*";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_SESSION_TARGET      = @"session:";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_TOKEN_TARGET        = @"token:";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_TIME_SERVICE_TARGET = @"time:";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_SUCCESS         = @"successCode";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TARGET          = @"target";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ERROR_CODE      = @"errorCode";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ERROR_DOM       = @"errorDomain";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ERROR_MSG       = @"errorMsg";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ACTIVATION_CMD  = @"activationCmd";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ACTIVATION_ID   = @"activationId";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_ALGORITHM_ID    = @"activationAlg";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_PROTO_VERSION   = @"activationProto";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_SESSION_GET     = @"get_session";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_SESSION_PUT     = @"put_session";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TOKEN_CMD       = @"tokenCmd";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TOKEN_NAME      = @"tokenName";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TOKEN_DATA      = @"tokenData";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TOKEN_NA        = @"tokenNotFound";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_TOKEN_GET       = @"get_token";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_TOKEN_PUT       = @"put_token";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_TOKEN_REMOVE    = @"remove_token";

PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TIME_SERVICE_CMD       = @"timeCmd";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TIME_SERVICE_LOCAL     = @"timeLocal";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TIME_SERVICE_DELTA     = @"timeDelta";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_KEY_TIME_SERVICE_PRECISION = @"timePrecision";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_TIME_SERVICE_GET       = @"get_time";
PA2_NO_EXPORT NSString * const PA2WCSessionPacket_CMD_TIME_SERVICE_PUT       = @"put_time";
