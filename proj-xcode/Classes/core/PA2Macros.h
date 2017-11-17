/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import <Foundation/Foundation.h>

#pragma mark - Custom logging

/**
 PALog(...) macro prints debug information into the debug console and is used internally
 in the PowerAuth SDK. By default, the macro is expanded to NSLog(...), but only for DEBUG 
 build configuration. You can control this behavior by defining following macros:
 
	ENABLE_PA2_LOG		- force enables debug logs
	DISABLE_PA2_LOG		- force disables debug logs
 
 If both, DISABLE_PA2_LOG and ENABLE_PA2_LOG are defined, then the compile error is produced.
 */
#if defined(DEBUG) && !defined(DISABLE_PA2_LOG) && !defined(ENABLE_PA2_LOG)
#define ENABLE_PA2_LOG
#endif

#if defined(DISABLE_PA2_LOG) && defined(ENABLE_PA2_LOG)
#error PowerAuth debug log is force disabled and enabled at the same time
#endif

#ifdef ENABLE_PA2_LOG
	#define PALog(...) NSLog(__VA_ARGS__)
#else
	#define PALog(...)
#endif



#pragma mark - Extern declaration

#ifdef __cplusplus
	// C++
	#define PA2_EXTERN_C				extern "C"
	#define PA2_EXTERN_C_BEGIN          extern "C" {
	#define PA2_EXTERN_C_END			}
#else
	// C
	#define PA2_EXTERN_C				extern
	#define PA2_EXTERN_C_BEGIN
	#define PA2_EXTERN_C_END
#endif

