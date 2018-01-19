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

/** Error code for error that occurs when activation state is ivalid */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationState;

/** Error code for error that occurs when activation data is ivalid */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationData;

/** Error code for error that occurs when activation is required but missing */
PA2_EXTERN_C NSInteger const PA2ErrorCodeMissingActivation;

/** Error code for error that occurs when authentication using PowerAuth signature fails */
PA2_EXTERN_C NSInteger const PA2ErrorCodeAuthenticationFailed;

/** Error code for error that occurs when pending activation is present and work with completed activation is required */
PA2_EXTERN_C NSInteger const PA2ErrorCodeActivationPending;

/** Error code for keychanin related errors */
PA2_EXTERN_C NSInteger const PA2ErrorCodeKeychain;

/** Error code for TouchID not available error */
PA2_EXTERN_C NSInteger const PA2ErrorCodeTouchIDNotAvailable;

/** Error code for TouchID action cancel error */
PA2_EXTERN_C NSInteger const PA2ErrorCodeTouchIDCancel;

/** Error code for cancelled operations */
PA2_EXTERN_C NSInteger const PA2ErrorCodeOperationCancelled;

/** Error code for errors related to end-to-end encryption */
PA2_EXTERN_C NSInteger const PA2ErrorCodeEncryption;

/** Error code for a general API misuse */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWrongParameter;

/** Error code for accessing an unknown token */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidToken;

/** Error code for a general error related to WatchConnectivity */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWatchConnectivity;
