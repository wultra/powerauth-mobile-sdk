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

#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

/**
 Macro for marking any interface as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: PA2_DEPRECATED(0.19.0)
 
 We're keeping deprecated API's up to the next major release of SDK. For example, if something
 is marked as deprecated in 0.18.x, then the interface will be removed in 0.19.0
 */
#define PA2_DEPRECATED(deprecated_in_version) __attribute__((deprecated))

/**
 Macro for making a whole protocol as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: PA2_DEPRECATED_PROTOCOL(1.6.0, OldProtocol, NewProtocol)
 */
#define PA2_DEPRECATED_PROTOCOL(deprecated_in_version, old, replacement)    \
    PA2_DEPRECATED(deprecated_in_version)                                   \
    @protocol old <replacement>                                             \
    @end

/**
 Macro for making a structure or enumeration as deprecated. You have to provide a version in
 which was this deprecation introduced. For example: PA2_DEPRECATED_TYPE(1.6.0, OldType, NewType)
 */
#define PA2_DEPRECATED_TYPE(deprecated_in_version, old, replacement)        \
    typedef replacement old PA2_DEPRECATED(deprecated_in_version);

/**
 Macro for making a whole class as deprecated. You have to provide a version in which was this
 deprecation introduced. For example: PA2_DEPRECATED_CLASS(1.6.0, OldClass, NewClass).
 This macro must be used in pair with PA2_DEPRECATED_CLASS_IMPL() to provide an implementation.
 */
#define PA2_DEPRECATED_CLASS(deprecated_in_version, old, replacement)       \
    PA2_DEPRECATED(deprecated_in_version)                                   \
    @interface old : replacement                                            \
    @end

/**
 Macro for making an implementation for previously declared deprecated class.
 For example: PA2_DEPRECATED_CLASS_IMPL(1.6.0, OldClass, NewClass).
 To ingore deprecated warnings, you can use the following pragma declaration:
 
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-implementations"
 
 ... deprecated implementations ...
 
 #pragma clang diagnostic pop
 */
#define PA2_DEPRECATED_CLASS_IMPL(deprecated_in_version, old, replacement)  \
    @implementation old                                                     \
    @end

#pragma mark - Extern declaration

#ifdef __cplusplus
    // C++
    #define PA2_EXTERN_C                extern "C"
    #define PA2_EXTERN_C_BEGIN          extern "C" {
    #define PA2_EXTERN_C_END            }
#else
    // C
    #define PA2_EXTERN_C                extern
    #define PA2_EXTERN_C_BEGIN
    #define PA2_EXTERN_C_END
#endif


#pragma mark - Apple platforms

#if TARGET_OS_TV == 0 && TARGET_OS_OSX == 0
    #define PA2_WATCH_SUPPORT
    #define PA2_BIOMETRY_SUPPORT
#endif

// PowerAuthCore module availability
#if !defined(PA2_EXTENSION_SDK)
    #define PA2_HAS_CORE_MODULE 1
#else
    #define PA2_HAS_CORE_MODULE 0
#endif

// LAContext availability
#if TARGET_OS_IOS == 1 || TARGET_OS_MACCATALYST == 1
    #define PA2_HAS_LACONTEXT 1
#else
    #define PA2_HAS_LACONTEXT 0
    #define LAContext NSObject
#endif

// SDK modules availability
#if PA2_HAS_CORE_MODULE
    // PowerAuth2 module
    #define PA2_MODULE_MAIN_SDK         1
    #define PA2_MODULE_WATCH_SDK        0
    #define PA2_MODULE_APPEXT_SDK       0
#else
    #if TARGET_OS_WATCH
        // PowerAuth2ForWatch module
        #define PA2_MODULE_MAIN_SDK     0
        #define PA2_MODULE_WATCH_SDK    1
        #define PA2_MODULE_APPEXT_SDK   0
    #else
        // PowerAuth2ForExtensions module
        #define PA2_MODULE_MAIN_SDK     0
        #define PA2_MODULE_WATCH_SDK    0
        #define PA2_MODULE_APPEXT_SDK   1
    #endif
#endif
