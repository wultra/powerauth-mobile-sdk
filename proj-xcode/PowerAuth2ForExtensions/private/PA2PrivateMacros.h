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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>
#import <PowerAuth2ForExtensions/PowerAuthErrorConstants.h>

// Check whether we're using C++ in Extensions SDK. If yes, then treat this as an error.
#if defined(__cplusplus) && defined(PA2_EXTENSION_SDK)
#error "Extensions SDK should not depend on C++"
#endif


/// Returns provided object instance if it's kind of desiredClass, otherwise nil.
/// Please use PA2ObjectAs macro instead of this function.
PA2_EXTERN_C id PA2CastToImpl(id object, Class desiredClass);

/// Returns provided object instance if implements the desired protocol, otherwise nil.
/// Please use PA2ObjectConformsTo macro instead of this function.
PA2_EXTERN_C id PA2CastToProtoImpl(id object, Protocol * desiredProtocol);

/**
 This macro returns the provided instance if it's kind of desiredClass, otherwise nil.
 Typical usage:
    NSDictionary * goodDictionary = @{ @"stringKey" : @"hello world" }
    NSDictionary * baadDictionary = @{ @"stringKey" : @(42) }
    NSString * correct = PA2ObjectAs(goodDictionary[@"stringKey", NSString);
    NSString * wrong   = PA2ObjectAs(baadDictionary[@"stringKey", NSString);
    // ..at the end of the day,
    //    "correct" is "hello world"
    //    and "wrong" is nil
 */
#define PA2ObjectAs(object, requiredClass) ((requiredClass*)(PA2CastToImpl(object, [requiredClass class])))

/**
 This macro returns the provided instance if it conforms the requested protocol, otherwise nil.
 */
#define PA2ConformsTo(object, requiredProtocol) ((id<requiredProtocol>)(PA2CastToProtoImpl(object, @protocol(requiredProtocol))))

/// Returns NSError with PA2ErrorDomain with given errorCode & message.
PA2_EXTERN_C NSError * PA2MakeError(PowerAuthErrorCode errorCode, NSString * message);
/// Returns NSError with PA2ErrorDomain with given errorCode, message and additional info.
PA2_EXTERN_C NSError * PA2MakeErrorInfo(NSInteger errorCode, NSString * message, NSDictionary * info);
/// Returns the default textual representation for given error code.
/// If message is provided, then returns this message instead of default string.
PA2_EXTERN_C NSString * PA2MakeDefaultErrorDescription(PowerAuthErrorCode errorCode, NSString * message);


#if DEBUG
/// Print error based on errno constant. Function is implemented only for DEBUG builds.
PA2_EXTERN_C void PA2PrintErrno(NSString * location);
#else
#define PA2PrintErrno(...)
#endif
