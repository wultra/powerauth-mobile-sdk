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
// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#import "PA2WCSessionPacket.h"

@class PA2WCSessionManager;

/**
 The PA2WCSessionDataHandler protocol defines interface for processing packets
 transmitted between Apple Watch and iPhone.
 */
@protocol PA2WCSessionDataHandler <NSObject>
@required

/**
 Implementation must return YES, if packet can be processed in this handler.
 */
- (BOOL) canProcessPacket:(PA2WCSessionPacket*)packet;

/**
 Implementation must always return response for given packet. The PA2WCSessionManager is calling
 this method only for handler which can process the packet (e.g. canProcessPacket was called before
 and method returned YES)
 */
- (PA2WCSessionPacket*) sessionManager:(PA2WCSessionManager*)manager responseForPacket:(PA2WCSessionPacket*)packet;

@end

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
