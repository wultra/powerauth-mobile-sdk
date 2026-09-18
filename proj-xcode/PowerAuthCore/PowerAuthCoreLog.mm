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

#import <PowerAuthCore/PowerAuthCoreLog.h>
#import <PowerAuth/Debug.h>
#include <atomic>

#ifdef ENABLE_POWERAUTH_CORE_LOG

static std::atomic<PowerAuthCoreLogCallback> s_log_callback { nullptr };

static void _WriteLog(NSString * message)
{
    auto callback = s_log_callback.load();
    if (callback) {
        callback(message);
    } else {
        NSLog(@"%@", message);
    }
}

static void _ForwardCC7Log(void * context, const char * message)
{
    @autoreleasepool {
        NSString * text = [NSString stringWithUTF8String:message];
        if (!text) {
            NSData * data = [NSData dataWithBytes:message length:strlen(message)];
            text = [NSString stringWithFormat:@"<non-UTF-8 log, Base64: %@>", [data base64EncodedStringWithOptions:0]];
        }
        _WriteLog([@"[cc7] " stringByAppendingString:text]);
    }
}

void PowerAuthCoreLogImpl(NSString * format, ...)
{
    if (!PowerAuthCoreLogIsEnabled()) {
        return;
    }
    va_list args;
    va_start(args, format);
    NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    _WriteLog([@"[PowerAuthCore] " stringByAppendingString:message]);
}

#endif // ENABLE_POWERAUTH_CORE_LOG

void PowerAuthCoreLogSetCallback(PowerAuthCoreLogCallback callback)
{
#ifdef ENABLE_POWERAUTH_CORE_LOG
    s_log_callback.store(callback);
    cc7::debug::SetLogHandler({ _ForwardCC7Log, nullptr });
#endif
}

void PowerAuthCoreLogSetEnabled(BOOL enabled)
{
    CC7_LOG_ENABLE(enabled);
}

BOOL PowerAuthCoreLogIsEnabled(void)
{
    return CC7_LOG_IS_ENABLED();
}

BOOL PowerAuthCoreHasDebugFeatures(void)
{
    BOOL debug_features = powerAuth::HasDebugFeaturesTurnedOn();
#if defined(ENABLE_POWERAUTH_CORE_LOG) || defined(DEBUG)
    debug_features |= YES;
#endif
    return debug_features;
}
