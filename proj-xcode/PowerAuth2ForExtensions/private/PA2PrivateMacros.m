/*
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
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2PrivateMacros.h"
#import <PowerAuth2ForExtensions/PowerAuthLog.h>

id PA2CastToImpl(id instance, Class desiredClass)
{
    if ([instance isKindOfClass:desiredClass]) {
        return instance;
    }
    return nil;
}

id PA2CastToProtoImpl(id instance, Protocol * proto)
{
    if ([instance conformsToProtocol:proto]) {
        return instance;
    }
    return nil;
}

#if DEBUG
void PA2PrintErrno(NSString * location)
{
    char buffer[256];
    strerror_r(errno, buffer, sizeof(buffer));
    NSString * error = [NSString stringWithUTF8String:buffer];
    PowerAuthLog(@"%@ failed: %@", location, error);
}
#endif // DEBUG
