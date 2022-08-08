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

#import "PA2WCSessionPacket_ActivationStatus.h"
#import "PA2PrivateMacros.h"

@implementation PA2WCSessionPacket_ActivationStatus

- (void) serializeToDictionary:(NSMutableDictionary *)dictionary
{
    if (_command) {
        dictionary[PA2WCSessionPacket_KEY_ACTIVATION_CMD] = _command;
    }
    if (_activationId) {
        dictionary[PA2WCSessionPacket_KEY_ACTIVATION_ID] = _activationId;
    }
}

- (id) initWithDictionary:(NSDictionary *)dictionary
{
    self = [super init];
    if (self) {
        _command = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_ACTIVATION_CMD], NSString);
        _activationId = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_ACTIVATION_ID], NSString);
    }
    return self;
}

- (BOOL) validatePacketData
{
    if ([_command isEqualToString:PA2WCSessionPacket_CMD_SESSION_PUT]) {
        return YES;
    } else if ([_command isEqualToString:PA2WCSessionPacket_CMD_SESSION_GET]) {
        return YES;
    }
    return NO;
}

@end
