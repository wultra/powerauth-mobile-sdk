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

#import "PowerAuthMacros.h"

#pragma mark - SDK logging

#if !defined(ENABLE_PA2_LOG)
#define ENABLE_PA2_LOG
#endif

#ifdef DISABLE_PA2_LOG
#warning DISABLE_PA2_LOG is no longer supported. Use PowerAuthLogSetEnabled(NO) in runtime.
#endif

#ifdef ENABLE_PA2_LOG

    // Implementations

    PA2_EXTERN_C void PowerAuthLogImpl(NSString * _Nonnull format, ...);

    // Macros

    /**
     Logs diagnostic information to PowerAuthLogDelegate and the system console.
     Logging is compiled in and enabled by default in all build configurations.
     */
    #define PowerAuthLog(...)               PowerAuthLogImpl(__VA_ARGS__)

#else
    // If PA2Log is disabled, then suppress whole log statement
    #define PowerAuthLog(...)

#endif // ENABLE_PA2_LOG

/**
 Enables or disables PowerAuth SDK, PowerAuthCore and cc7 logging.
 Enabled by default in all build configurations. Critical warnings remain enabled.
 */
PA2_EXTERN_C void PowerAuthLogSetEnabled(BOOL enabled);

/**
 Returns YES if internal PowerAuth SDK logging is enabled.
 */
PA2_EXTERN_C BOOL PowerAuthLogIsEnabled(void);

/**
 Enables or disables verbose PowerAuth SDK logging. Enabled by default.
 Diagnostic logs may contain passwords, cryptographic keys and request or response data.
 */
PA2_EXTERN_C void PowerAuthLogSetVerbose(BOOL verbose);

/**
 Returns YES if verbose PowerAuth SDK logging is enabled.
 */
PA2_EXTERN_C BOOL PowerAuthLogIsVerbose(void);

/**
 Enables or disables NSLog output for PowerAuth SDK, PowerAuthCore and cc7 logs.
 Enabled by default. Delegate delivery is unaffected, and critical warnings always reach the console.
 */
PA2_EXTERN_C void PowerAuthLogToConsoleSetEnabled(BOOL enabled);

/**
 Returns YES if logging to the system console is enabled.
 */
PA2_EXTERN_C BOOL PowerAuthLogToConsoleIsEnabled(void);

/**
 Reports a critical warning to the delegate and the system console.
 Critical warnings are delivered even when logging or console output is disabled.
 */
PA2_EXTERN_C void PowerAuthCriticalWarning(NSString * _Nonnull format, ...);

/**
 Receives PowerAuth SDK, PowerAuthCore and cc7 diagnostic logs in all build configurations.
 Native messages include a source prefix. Messages may contain sensitive data, including keys and passwords.
 Calls are synchronous on the logging thread and may arrive concurrently; implementations must be thread-safe.
 Messages emitted before registration are not replayed.

 Logs also reach NSLog by default; PowerAuthLogToConsoleSetEnabled controls console output.
 */
@protocol PowerAuthLogDelegate
/**
 Log message reported by the library.
 */
- (void) powerAuthLog:(nonnull NSString*)log;
@end

/**
 Sets the retained delegate for SDK, PowerAuthCore and cc7 logs. Passing nil removes it.
 Calls already in progress may still reach the previous delegate.
 */
PA2_EXTERN_C void PowerAuthLogSetDelegate(id<PowerAuthLogDelegate> _Nullable delegate);
