/**
 * Copyright 2016 Wultra s.r.o.
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

#pragma mark - Error codes

/** PowerAuth SDK error domain */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorDomain;

/**
 A key to NSError.userInfo dicionary where the optional NSDictionary with additional
 information about error is stored.
 */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorInfoKey_AdditionalInfo;
/**
 A key to NSError.userInfo dicionary where the optional NSData with error response
 is stored.
 */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorInfoKey_ResponseData;

/** Error code for error with network connectivity or download */
PA2_EXTERN_C NSInteger const PA2ErrorCodeNetworkError;

/** Error code for error in signature calculation */
PA2_EXTERN_C NSInteger const PA2ErrorCodeSignatureError;

/** Error code for error that occurs when activation state is invalid */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationState;

/** Error code for error that occurs when activation data is invalid */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationData;

/** Error code for error that occurs when activation is required but missing */
PA2_EXTERN_C NSInteger const PA2ErrorCodeMissingActivation;

/** Error code for error that occurs when pending activation is present and work with completed activation is required */
PA2_EXTERN_C NSInteger const PA2ErrorCodeActivationPending;

/** Error code for TouchID or FaceID not available error */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryNotAvailable;

/** Error code for TouchID or FaceID action cancel error */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryCancel;

/**
 Error code for biometric authentication failure. This can happen when biometric authentication is requested
 and is not configured, or when failed to acquire biometry key from the keychain.
 */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryFailed;

/**
 Error code for canceled operation. This kind of error may occur in situations, when SDK
 needs to cancel an asynchronous operation, but the cancel is not initiated by the application
 itself. For example, if you reset the state of `PowerAuthSDK` during the pending
 fetch for activation status, then the application gets an exception, with this error code.
 */
PA2_EXTERN_C NSInteger const PA2ErrorCodeOperationCancelled;

/** Error code for errors related to end-to-end encryption */
PA2_EXTERN_C NSInteger const PA2ErrorCodeEncryption;

/** Error code for a general API misuse */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWrongParameter;

/** Error code for accessing an unknown token */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidToken;

/** Error code for a general error related to WatchConnectivity */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWatchConnectivity;

/**
 Error code for protocol upgrade failure.
 The recommended action is to retry the status fetch operation, or locally remove the activation.
 */
PA2_EXTERN_C NSInteger const PA2ErrorCodeProtocolUpgrade;
/**
 The requested function is not available during the protocol upgrade. You can retry the operation,
 after the upgrade is finished.
 */
PA2_EXTERN_C NSInteger const PA2ErrorCodePendingProtocolUpgrade;
