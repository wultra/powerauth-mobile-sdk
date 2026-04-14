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

#import "PA2WCSessionDataHandler.h"
#import "PA2PrivateMacros.h"

#if defined(PA2_WATCH_SUPPORT)

@implementation PA2WCSessionDataHandlerResponse
{
    void(^_completionCallback)(PA2WCSessionPacket * response);
}

- (instancetype) initWithResponsePacket:(PA2WCSessionPacket *)responsePacket
{
    self = [super init];
    if (self) {
        _responsePacket = responsePacket;
        _delayedCompletion = responsePacket == nil;
    }
    return self;
}

+ (instancetype) asyncResponse
{
    return [[PA2WCSessionDataHandlerResponse alloc] initWithResponsePacket:nil];
}

+ (instancetype) responseWithPacket:(PA2WCSessionPacket*)responsePacket
{
    return [[PA2WCSessionDataHandlerResponse alloc] initWithResponsePacket:responsePacket];
}

+ (instancetype) responseWithError:(NSError*)error
{
    return [self responseWithPacket:[PA2WCSessionPacket packetWithError:error]];
}

+ (instancetype) responseWithErrorMessage:(NSString*)errorMessage
{
    NSError * error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, errorMessage);
    return [self responseWithPacket:[PA2WCSessionPacket packetWithError:error]];
}

- (void) setCompletionCallback:(void (^)(PA2WCSessionPacket *))completionCallback
{
    PA2WCSessionPacket * packetToReport = nil;
    @synchronized (self) {
        if (_delayedCompletion && !_completionCallback) {
            if (_responsePacket) {
                // Response is already known
                packetToReport = packetToReport;
            } else {
                // Otherwise keep callback for later
                _completionCallback = completionCallback;
            }
        }
    }
    // Complete outside of locked section.
    if (packetToReport && completionCallback) {
        completionCallback(packetToReport);
    }
}

- (void) completeWithResponsePacket:(PA2WCSessionPacket *)responsePacket
{
    void(^completionCallback)(PA2WCSessionPacket * response) = nil;
    @synchronized (self) {
        if (_delayedCompletion && !_responsePacket) {
            _responsePacket = responsePacket;
            if (_completionCallback) {
                completionCallback = _completionCallback;
                _completionCallback = nil;
            }
        }
    }
    // Complete outside of locked section.
    if (completionCallback) {
        completionCallback(responsePacket);
    }
}

- (void) completeWithError:(NSError *)error
{
    [self completeWithResponsePacket:[PA2WCSessionPacket packetWithError:error]];
}

@end

#endif // defined(PA2_WATCH_SUPPORT)
