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

#import "PA2WCSessionPacket.h"

/**
 The PA2WCSessionPacket_ActivationStatus object contains information
 about session activation.
 */
@interface PA2WCSessionPacket_ActivationStatus : NSObject<PA2WCSessionPacketData>

/**
 Supported commands:
    PA2WCSessionPacket_CMD_SESSION_GET - when watchOS is asking for actual status of the session
        - response is PA2WCSessionPacket_CMD_SESSION_PUT
    PA2WCSessionPacket_CMD_SESSION_PUT - when IOS is pushing status to the watchOS.
 */
@property (nonatomic, strong) NSString * command;

/**
 Optional and has meaning only when command == PA2WCSessionPacket_CMD_SESSION_PUT.
 In this case, presence of activationId determining whether the session is activated or not.
 */
@property (nonatomic, strong) NSString * activationId;
/**
 Optional and has meaning only when activationId is also present. The value contains the current
 PowerAuth algorithm in the string representation (e.g. `"EC_P384_ML_L3"`).
 */
@property (nonatomic, strong) NSString * algorithm;
/**
 Optional and has meaning only when activationId is also present. The value contains the current
 protocol version in string representation (e.g. `"3.3"`, `"4.0"`, etc.)
 */
@property (nonatomic, strong) NSString * protocolVersion;

@end
