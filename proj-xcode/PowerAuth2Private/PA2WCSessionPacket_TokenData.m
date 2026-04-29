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

#import "PA2WCSessionPacket_TokenData.h"
#import "PA2PrivateMacros.h"

@implementation PA2WCSessionPacket_TokenData

- (void) serializeToDictionary:(NSMutableDictionary *)dictionary
{
    if (_command) {
        dictionary[PA2WCSessionPacket_KEY_TOKEN_CMD] = _command;
    }
    if (_tokenName) {
        dictionary[PA2WCSessionPacket_KEY_TOKEN_NAME] = _tokenName;
    }
    if (_tokenData) {
        dictionary[PA2WCSessionPacket_KEY_TOKEN_DATA] = [_tokenData base64EncodedStringWithOptions:0];
    }
    if (_tokenNotFound) {
        dictionary[PA2WCSessionPacket_KEY_TOKEN_NA] = @YES;
    }
}

- (id) initWithDictionary:(NSDictionary *)dictionary
{
    self = [super init];
    if (self) {
        _command = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_TOKEN_CMD], NSString);
        _tokenName = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_TOKEN_NAME], NSString);
        NSString * tokenDataStr = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_TOKEN_DATA], NSString);
        _tokenData = tokenDataStr ? [[NSData alloc] initWithBase64EncodedString:tokenDataStr options:0] : nil;
        _tokenNotFound = PA2ObjectAs([dictionary objectForKey:PA2WCSessionPacket_KEY_TOKEN_NA], NSNumber).boolValue;
    }
    return self;
}

- (BOOL) validatePacketData
{
    BOOL hasName = _tokenName.length > 0;
    if ([_command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_GET]) {
        return hasName;
    } else if ([_command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_PUT]) {
        BOOL hasContent = _tokenData.length > 0 || _tokenNotFound;
        return hasName && hasContent;
    } else if ([_command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_REMOVE]) {
        return hasName;
    }
    return NO;
}

@end
