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

#if defined(DEBUG) && !defined(ENABLE_POWERAUTH_CORE_LOG)
#define ENABLE_POWERAUTH_CORE_LOG
#endif

#ifdef ENABLE_POWERAUTH_CORE_LOG
	/**
	 PowerAuthCoreLog(...) macro prints a debug information into the debug console and is used internally
	 in the PowerAuthCore library. For DEBUG builds, the macro is expanded to internal function which uses NSLog().
	 For RELEASE builds, the message is completely suppressed during the compilation.
	 */
	POWERAUTH_EXTERN_C void PowerAuthCoreLogImpl(NSString * format, ...);
	#define PowerAuthCoreLog(...) PowerAuthCoreLogImpl(__VA_ARGS__)

#else
	// If PowerAuthCoreLog is disabled, then disable everything
	#define PowerAuthCoreLog(...)

#endif // ENABLE_POWERAUTH_CORE_LOG

/**
 Function enables or disables internal PowerAuthCore logging.
 Note that it's effective only when library is compiled in DEBUG build configuration.
 */
POWERAUTH_EXTERN_C void PowerAuthCoreLogSetEnabled(BOOL enabled);

/**
 Function returns YES if internal PowerAuthCore logging is enabled.
 Note that when library is compiled in RELEASE configuration, then always returns NO.
 */
POWERAUTH_EXTERN_C BOOL PowerAuthCoreLogIsEnabled(void);
