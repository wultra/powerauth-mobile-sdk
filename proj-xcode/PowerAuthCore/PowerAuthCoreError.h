/*
 * Copyright 2025 Wultra s.r.o.
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

///  PowerAuthCore module error domain.
POWERAUTH_EXTERN_C NSString * __nonnull const PowerAuthCoreErrorDomain;

/// A key to `NSError.userInfo` dictionary where the optional `NSArray` with additional
/// information about error is stored.
POWERAUTH_EXTERN_C NSString * __nonnull const PowerAuthCoreErrorInfoKey_AdditionalErrors;

/// Error codes returned for `PowerAuthCoreErrorDomain` errors.
typedef NS_ENUM(NSInteger, PowerAuthCoreError) {
    PowerAuthCoreError_NA,
    PowerAuthCoreError_MissingActivation,
    PowerAuthCoreError_WrongActivationState,
    PowerAuthCoreError_WrongParameter,
    PowerAuthCoreError_BiometryNotAllowed,
    PowerAuthCoreError_NotAllowed,
    PowerAuthCoreError_TimeNotSynchronized,
    PowerAuthCoreError_InvalidData,
    PowerAuthCoreError_InvalidResponse,
    PowerAuthCoreError_InternalError,
    PowerAuthCoreError_Cryptography,
    PowerAuthCoreError_Canceled,
    PowerAuthCoreError_PendingProtocolUpgrade,
    PowerAuthCoreError_Other
};

@interface NSError (PowerAuthCoreError)

/// Contains `PowerAuthCoreError` in case that NSError object has `PowerAuthCoreErrorDomain`. If error object
/// has different domain, then property contains `PowerAuthCoreError_NA`.
@property (nonatomic, readonly) PowerAuthCoreError powerAuthCoreError;

/// Contains array with strings containing additional error messages, in case that more than one error message
/// was created with the failure.
@property (nonatomic, strong, nullable, readonly) NSArray<NSString*> * powerAuthCoreAdditionalErrorMessages;

@end
