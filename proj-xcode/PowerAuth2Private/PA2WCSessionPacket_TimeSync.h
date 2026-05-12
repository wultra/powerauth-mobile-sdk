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

#import "PA2WCSessionPacket.h"

/// The `PA2WCSessionPacket_TimeSync` contains information required for
/// the time synchronization on watchOS.
@interface PA2WCSessionPacket_TimeSync : NSObject<PA2WCSessionPacketData>

/// Supported commands:
/// - PA2WCSessionPacket_CMD_TIME_SERVICE_GET - when watchOS is asking for synchronized time.
///   - response is PA2WCSessionPacket_CMD_TIME_SERVICE_PUT
/// - PA2WCSessionPacket_CMD_TIME_SERVICE_PUT - when iOS wants to send information about synchronized time to watchOS.
///   - response is "Success" packet
@property (nonatomic, strong) NSString * command;

/// Contains current time on iOS, synchronized with the server.
@property (nonatomic, assign) NSTimeInterval localTime;
/// Contains calculated local time difference against the server.
@property (nonatomic, assign) NSTimeInterval localTimeAdjustment;
/// Contains value representing a maximum absolute deviation of synchronized time against the actual time on the server.
@property (nonatomic, assign) NSTimeInterval localTimeAdjustmentPrecision;

@end
