/**
 * Copyright 2018 Lime - HighTech Solutions s.r.o.
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

#pragma mark - Core logging

#if defined(DEBUG) && !defined(ENABLE_PA2_CORE_LOG)
#define ENABLE_PA2_CORE_LOG
#endif

#ifdef ENABLE_PA2_CORE_LOG

	// Implementations

	PA2_EXTERN_C void PA2CoreLogImpl(NSString * format, ...);
	PA2_EXTERN_C void PA2CoreLogSetEnabledImpl(BOOL enabled);
	PA2_EXTERN_C BOOL PA2CoreLogIsEnabledImpl(void);

	// Macros

	/**
	 PA2CoreLog(...) macro prints a debug information into the debug console and is used internally
	 in the PowerAuthCore library. For DEBUG builds, the macro is expanded to internal function which uses NSLog().
	 For RELEASE builds, the message is completely suppressed during the compilation.
	 */
	#define PA2CoreLog(...) 				PA2CoreLogImpl(__VA_ARGS__)
	/**
	 PA2CoreLogSetEnabled(BOOL enabled) disables or enables PA2Log() messages.
	 */
	#define PA2CoreLogSetEnabled(enabled)	PA2CoreLogSetEnabledImpl(enabled)
	/**
	 BOOL PA2CoreLogIsEnabled() returns current status of PA2Log() macro logging.
	 */
	#define PA2CoreLogIsEnabled()			PA2CoreLogIsEnabledImpl()

#else
	// If PA2Log is disabled, then disable everything
	#define PA2CoreLog(...)
	#define PA2CoreLogSetEnabled(enabled)
	#define PA2CoreLogIsEnabled() 			NO

#endif // ENABLE_PA2_CORE_LOG
