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

#import "PA2Macros.h"

// Key used in userInfo, transmitted over the
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_USER_INFO_KEY;

// value for "target" property, when response is transmitted.
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_RESPONSE_TARGET;
// Prefix for all session related messages
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_SESSION_TARGET;
// Prefix for all token related messages
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_TOKEN_TARGET;


// Constants for serializing general packet
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_TARGET;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_ERROR_CODE;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_ERROR_DOM;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_ERROR_MSG;

// Constants for serializing activation status
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_ACTIVATION_CMD;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_ACTIVATION_ID;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_CMD_SESSION_GET;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_CMD_SESSION_PUT;

// Constants for serializing token related data
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_TOKEN_CMD;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_TOKEN_NAME;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_TOKEN_DATA;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_TOKEN_NA;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_CMD_TOKEN_GET;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_CMD_TOKEN_PUT;
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_CMD_TOKEN_REMOVE;

// Generic success
PA2_EXTERN_C NSString * __nonnull const PA2WCSessionPacket_KEY_SUCCESS;
