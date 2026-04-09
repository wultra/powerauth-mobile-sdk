/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PA2WCSessionPacket_TimeSync.h"
#import "PA2PrivateMacros.h"

@implementation PA2WCSessionPacket_TimeSync

static inline NSTimeInterval _ValueToInterval(id value)
{
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber*)value doubleValue];
    }
    return 0.0;
}

static inline BOOL _IsValidInterval(NSTimeInterval interval, BOOL allow_negative)
{
    if (isnan(interval)) {
        return NO;
    }
    return allow_negative || interval >= 0.0;
}

- (id) initWithDictionary:(NSDictionary *)dictionary
{
    self = [super init];
    if (self) {
        _command = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_CMD], NSString);
        _localTime = _ValueToInterval(dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_LOCAL]);
        _localTimeAdjustment = _ValueToInterval(dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_DELTA]);
        _localTimeAdjustmentPrecision = _ValueToInterval(dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_PRECISION]);
    }
    return self;
}

- (void) serializeToDictionary:(NSMutableDictionary *)dictionary
{
    if (_command) {
        dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_CMD] = _command;
    }
    dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_LOCAL]     = @(_localTime);
    dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_DELTA]     = @(_localTimeAdjustment);
    dictionary[PA2WCSessionPacket_KEY_TIME_SERVICE_PRECISION] = @(_localTimeAdjustmentPrecision);
}

- (BOOL) validatePacketData
{
    return ([_command isEqualToString:PA2WCSessionPacket_CMD_TIME_SERVICE_GET] ||
            [_command isEqualToString:PA2WCSessionPacket_CMD_TIME_SERVICE_PUT]) &&
            _IsValidInterval(_localTime, NO) &&
            _IsValidInterval(_localTimeAdjustment, YES) &&
            _IsValidInterval(_localTimeAdjustmentPrecision, NO);
}

@end
