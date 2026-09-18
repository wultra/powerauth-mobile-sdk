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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

#pragma mark - Core logging

#if !defined(ENABLE_POWERAUTH_CORE_LOG)
#define ENABLE_POWERAUTH_CORE_LOG
#endif

#ifdef ENABLE_POWERAUTH_CORE_LOG
    /**
     Logs diagnostic information from PowerAuthCore in all build configurations.
     Messages go to the registered callback, or to NSLog when no callback is set.
     */
    POWERAUTH_EXTERN_C void PowerAuthCoreLogImpl(NSString * _Nonnull format, ...);
    #define PowerAuthCoreLog(...) PowerAuthCoreLogImpl(__VA_ARGS__)

#else
    // If PowerAuthCoreLog is disabled, then disable everything
    #define PowerAuthCoreLog(...)

#endif // ENABLE_POWERAUTH_CORE_LOG

/**
 Enables or disables PowerAuthCore and cc7 logging. Enabled by default in all build configurations.
 */
POWERAUTH_EXTERN_C void PowerAuthCoreLogSetEnabled(BOOL enabled);

/**
 Returns YES if PowerAuthCore and cc7 logging is enabled.
 */
POWERAUTH_EXTERN_C BOOL PowerAuthCoreLogIsEnabled(void);

/**
 Receives a formatted PowerAuthCore or cc7 message, including its source prefix.
 The callback runs synchronously on the logging thread and may be called concurrently.
 */
typedef void (*PowerAuthCoreLogCallback)(NSString * _Nonnull message);

/**
 Sets the callback for PowerAuthCore and cc7 logs, replacing their default console output.
 Passing NULL restores console output. Calls already in progress may use the previous callback.
 PowerAuth2 installs its own callback to forward these messages to PowerAuthLogDelegate.
 */
POWERAUTH_EXTERN_C void PowerAuthCoreLogSetCallback(PowerAuthCoreLogCallback _Nullable callback);

/// Contain s YES if PowerAuthCore module was compiled with a debug features. It is highly recommended
/// to check this flag and force application to crash if the production, final application
/// is running against the debug featured library.
POWERAUTH_EXTERN_C BOOL PowerAuthCoreHasDebugFeatures(void);
