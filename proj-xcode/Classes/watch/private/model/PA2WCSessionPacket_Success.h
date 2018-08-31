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
 The PA2WCSessionPacket_Success object is payload for generic success responses.
 The calling service must expect this kind of object in the response.
 */
@interface PA2WCSessionPacket_Success : NSObject<PA2WCSessionPacketData>

@property (nonatomic, assign) NSInteger successCode;

- (id) initWithCode:(NSInteger)successCode;

@end
