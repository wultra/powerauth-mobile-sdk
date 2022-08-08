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

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

#pragma mark - SDK logging

#if defined(DEBUG) && !defined(ENABLE_PA2_LOG)
#define ENABLE_PA2_LOG
#endif

#ifdef DISABLE_PA2_LOG
#warning DISABLE_PA2_LOG is no longer supported. Use PowerAuthLogSetEnabled(NO) in runtime.
#endif

#ifdef ENABLE_PA2_LOG

    // Implementations

    PA2_EXTERN_C void PowerAuthLogImpl(NSString * format, ...);

    // Macros

    /**
     PowerAuthLog(...) macro prints a debug information into the debug console and is used internally
     in the PowerAuth SDK. For DEBUG builds, the macro is expanded to internal function which uses NSLog().
     For RELEASE builds, the message is completely suppressed during the compilation.
     */
    #define PowerAuthLog(...)               PowerAuthLogImpl(__VA_ARGS__)

#else
    // If PA2Log is disabled, then suppress whole log statement
    #define PowerAuthLog(...)

#endif // ENABLE_PA2_LOG

/**
 Function enables or disables internal PowerAuth SDK logging.
 Note that it's effective only when library is compiled in DEBUG build configuration.
 */
PA2_EXTERN_C void PowerAuthLogSetEnabled(BOOL enabled);

/**
 Function returns YES if internal PowerAuth SDK logging is enabled.
 Note that when library is compiled in RELEASE configuration, then always returns NO.
 */
PA2_EXTERN_C BOOL PowerAuthLogIsEnabled(void);

/**
 Function sets internal PowerAuth SDK logging to more verbose mode.
 Note that it's effective only when library is compiled in DEBUG build configuration.
 */
PA2_EXTERN_C void PowerAuthLogSetVerbose(BOOL verbose);

/**
 Function returns YES if internal PowerAuth SDK logging is more talkative than usual.
 Note that when library is compiled in RELEASE configuration, then always returns NO.
 */
PA2_EXTERN_C BOOL PowerAuthLogIsVerbose(void);

/**
 PA2CriticalWarning(...) function prints a critical warning information into the debug console and
 is used internally in the PowerAuth SDK. This kind of warnings are always printed to the DEBUG
 console and cannot be supressed by configuration.
 */
PA2_EXTERN_C void PowerAuthCriticalWarning(NSString * format, ...);
