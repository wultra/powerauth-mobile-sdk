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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import "PowerAuthLog.h"

#if PA2_HAS_CORE_MODULE
#import <PowerAuthCore/PowerAuthCore.h>
#else
#define PowerAuthCoreLogSetEnabled(x)
#endif

#ifdef ENABLE_PA2_LOG
static BOOL s_log_enabled = YES;
static BOOL s_log_verbose = YES;
static BOOL s_log_to_console = YES;
static id<PowerAuthLogDelegate> s_log_delegate = nil;

#if PA2_HAS_CORE_MODULE
static void _ForwardCoreLog(NSString * message)
{
    PowerAuthLogImpl(@"%@", message);
}
#endif

static NSObject * _LogLock(void)
{
    static NSObject * lock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
#if PA2_HAS_CORE_MODULE
        PowerAuthCoreLogSetCallback(_ForwardCoreLog);
#endif
    });
    return lock;
}

static void _WriteLog(NSString * message, BOOL critical)
{
    id<PowerAuthLogDelegate> delegate;
    BOOL logToConsole;
    @synchronized (_LogLock()) {
        if (!critical && !s_log_enabled) {
            return;
        }
        delegate = s_log_delegate;
        logToConsole = critical || s_log_to_console;
    }
    if (delegate) {
        [delegate powerAuthLog:message];
    }
    if (logToConsole) {
        NSLog(@"[PowerAuth] %@", message);
    }
}

void PowerAuthLogImpl(NSString * format, ...)
{
    if (!PowerAuthLogIsEnabled()) {
        return;
    }
    va_list args;
    va_start(args, format);
    NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    _WriteLog(message, NO);
}
#endif // ENABLE_PA2_LOG


void PowerAuthLogSetEnabled(BOOL enabled)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        s_log_enabled = enabled;
        PowerAuthCoreLogSetEnabled(enabled);
    }
#endif
}

BOOL PowerAuthLogIsEnabled(void)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        return s_log_enabled;
    }
#else
    return NO;
#endif
}

void PowerAuthLogSetVerbose(BOOL verbose)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        s_log_verbose = verbose;
    }
#endif
}

BOOL PowerAuthLogIsVerbose(void)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        return s_log_verbose;
    }
#else
    return NO;
#endif
}

void PowerAuthLogToConsoleSetEnabled(BOOL enabled)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        s_log_to_console = enabled;
    }
#endif
}

BOOL PowerAuthLogToConsoleIsEnabled(void)
{
#ifdef ENABLE_PA2_LOG
    @synchronized (_LogLock()) {
        return s_log_to_console;
    }
#else
    return NO;
#endif
}

void PowerAuthCriticalWarning(NSString * format, ...)
{
    va_list args;
    va_start(args, format);
    NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
#ifdef ENABLE_PA2_LOG
    _WriteLog([@"CRITICAL WARNING: " stringByAppendingString:message], YES);
#else
    NSLog(@"[PowerAuth] CRITICAL WARNING: %@", message);
#endif
}

void PowerAuthLogSetDelegate(id<PowerAuthLogDelegate> delegate)
{
#ifdef ENABLE_PA2_LOG
    // Delegate destruction can itself log, so release it outside the logging lock.
    __attribute__((objc_precise_lifetime)) id<PowerAuthLogDelegate> previousDelegate;
    @synchronized (_LogLock()) {
        previousDelegate = s_log_delegate;
        s_log_delegate = delegate;
    }
    (void) previousDelegate;
#endif
}
