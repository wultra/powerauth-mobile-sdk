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

#import "PA2WCSessionPacket_Success.h"
#import "PA2PrivateMacros.h"

@implementation PA2WCSessionPacket_Success

- (id) initWithCode:(NSInteger)successCode
{
    self = [super init];
    if (self) {
        _successCode = successCode;
    }
    return self;
}

- (id) initWithDictionary:(NSDictionary*)dictionary
{
    NSNumber * num = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_SUCCESS], NSNumber);
    if (num == nil) {
        return nil;
    }
    self = [super init];
    if (self) {
        _successCode = [num integerValue];
    }
    return self;
}

- (void) serializeToDictionary:(NSMutableDictionary*)dictionary
{
    dictionary[PA2WCSessionPacket_KEY_SUCCESS] = @(_successCode);
}

- (BOOL) validatePacketData
{
    // always valid, because initWithDictionary returns nil when content is invalid.
    return YES;
}

@end
