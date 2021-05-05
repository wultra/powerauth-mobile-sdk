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

#import <Foundation/Foundation.h>

/**
 Macro for marking interface as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: POWERAUTH_DEPRECATED(0.19.0)
 
 We're keeping deprecated API's up to the next major release of SDK. For example, if something
 is marked as deprecated in 0.18.x, then the interface will be removed in 0.19.0
 */
#define POWERAUTH_DEPRECATED(deprecated_in_version) __attribute__((deprecated))

/**
 Macro for making a whole protocol as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: POWERAUTH_DEPRECATED_PROTOCOL(1.6.0, OldProtocol, NewProtocol)
 */
#define POWERAUTH_DEPRECATED_PROTOCOL(deprecated_in_version, old, replacement)	\
	POWERAUTH_DEPRECATED(deprecated_in_version)									\
	@protocol old <replacement>													\
	@end

/**
 Macro for making a structure or enumeration as deprecated. You have to provide a version in
 which was this deprecation introduced. For example: POWERAUTH_DEPRECATED_TYPE(1.6.0, OldType, NewType)
 */
#define POWERAUTH_DEPRECATED_TYPE(deprecated_in_version, old, replacement)		\
	typedef replacement old POWERAUTH_DEPRECATED(deprecated_in_version);

/**
 Macro for making a whole class as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: POWERAUTH_DEPRECATED_CLASS(1.6.0, OldClass, NewClass).
 This macro must be used in pair with POWERAUTH_DEPRECATED_CLASS_IMPL() to provide an implementation.
 */
#define POWERAUTH_DEPRECATED_CLASS(deprecated_in_version, old, replacement)		\
	POWERAUTH_DEPRECATED(deprecated_in_version)									\
	@interface old : replacement												\
	@end

/**
 Macro for making an implementation for previously declared deprecated class.
 For example: POWERAUTH_DEPRECATED_CLASS_IMPL(1.6.0, OldClass, NewClass).
 To ingore deprecated warnings, you can use the following pragma declaration:
 
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-implementations"
 
 ... deprecated implementations ...
 
 #pragma clang diagnostic pop
 */
#define POWERAUTH_DEPRECATED_CLASS_IMPL(deprecated_in_version, old, replacement)	\
	@implementation old																\
	@end

#pragma mark - Extern declaration

#ifdef __cplusplus
	// C++
	#define POWERAUTH_EXTERN_C				extern "C"
	#define POWERAUTH_EXTERN_C_BEGIN        extern "C" {
	#define POWERAUTH_EXTERN_C_END			}
#else
	// C
	#define POWERAUTH_EXTERN_C				extern
	#define POWERAUTH_EXTERN_C_BEGIN
	#define POWERAUTH_EXTERN_C_END
#endif
