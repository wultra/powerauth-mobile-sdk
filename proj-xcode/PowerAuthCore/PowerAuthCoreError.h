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

/// A key to `NSError.userInfo` dictionary where the optional `NSError` object re-created
/// from the underlying C++ core failure is stored.
POWERAUTH_EXTERN_C NSString * __nonnull const PowerAuthCoreErrorInfoKey_CoreError;

/// Error codes returned for `PowerAuthCoreErrorDomain` errors.
typedef NS_ENUM(NSInteger, PowerAuthCoreError) {
    PowerAuthCoreError_NA,
    /// Session has no activation but activation is required for the operation.
    PowerAuthCoreError_MissingActivation = 1,
    /// Activation is in wrong state for the requested operation.
    PowerAuthCoreError_WrongActivationState,
    /// Wrong input parameter provided.
    PowerAuthCoreError_WrongParameter,
    /// Biometry factor is not configured.
    PowerAuthCoreError_BiometryNotAllowed,
    /// Operation is not allowed in the current object's state. For example,
    /// if you try to already used encryptor object.
    PowerAuthCoreError_NotAllowed,
    /// Operation require synchronized time.
    PowerAuthCoreError_TimeNotSynchronized,
    /// Invalid data. Error is reported in situations, when SDK configuration data format is not valid.
    PowerAuthCoreError_InvalidData,
    /// Invalid response received from the server.
    PowerAuthCoreError_InvalidResponse,
    /// Digital or JWS signature is not valid.
    PowerAuthCoreError_WrongSignature,
    /// Internal library error.
    PowerAuthCoreError_InternalError,
    /// Operation failed in the cryptographic provider.
    PowerAuthCoreError_Cryptography,
    /// Operation was canceled from elsewhere.
    PowerAuthCoreError_Canceled,
    /// Operation is not allowed due to pending protocol upgrade. Try again later.
    PowerAuthCoreError_PendingProtocolUpgrade,
	/// Other, unspecified type of error.
    PowerAuthCoreError_Other,
    /// Unknown activation data.
    PowerAuthCoreError_InvalidActivationData,
    /// Upgrade SDK is required. A newer version of local activation data detected.
    PowerAuthCoreError_UpgradeSDK,
};

@interface NSError (PowerAuthCoreError)

/// Contains `PowerAuthCoreError` in case that NSError object has `PowerAuthCoreErrorDomain`. If error object
/// has different domain, then property contains `PowerAuthCoreError_NA`.
@property (nonatomic, readonly) PowerAuthCoreError powerAuthCoreErrorCode;

/// Contains array with strings containing additional error messages, in case that more than one error message
/// was created with the failure.
@property (nonatomic, strong, nullable, readonly) NSArray<NSString*> * powerAuthCoreAdditionalErrorMessages;

@end
