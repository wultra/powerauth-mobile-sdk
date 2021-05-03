/*
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

// This header contains all deprecated PA2* interfaces

//
// MARK: - 1.6.0 deprecated -
//

#import <PowerAuth2/PowerAuthClientConfiguration.h>
#import <PowerAuth2/PowerAuthActivationCode.h>
#import <PowerAuth2/PowerAuthActivationStatus.h>
#import <PowerAuth2/PowerAuthActivationResult.h>
#import <PowerAuth2/PowerAuthAuthorizationHttpHeader.h>
#import <PowerAuth2/PowerAuthActivationRecoveryData.h>
#import <PowerAuth2/PowerAuthErrorConstants.h>
#import <PowerAuth2/PowerAuthKeychainConfiguration.h>
#import <PowerAuth2/PowerAuthKeychain.h>
#import <PowerAuth2/PowerAuthSystem.h>
#import <PowerAuth2/PowerAuthWCSessionManager.h>
#import <PowerAuth2/PowerAuthRestApiErrorResponse.h>
#import <PowerAuth2/PowerAuthOperationTask.h>
#import <PowerAuth2/PowerAuthCustomHeaderRequestInterceptor.h>
#import <PowerAuth2/PowerAuthClientSslNoValidationStrategy.h>
#import <PowerAuth2/PowerAuthBasicHttpAuthenticationRequestInterceptor.h>

/**
 The PA2ClientConfiguration is now deprecated, please use PowerAuthClientConfiguration as a replacement.
 */
typedef PowerAuthClientConfiguration PA2ClientConfiguration PA2_DEPRECATED(1.6.0);
/**
 The PA2HttpRequestInterceptor protocol is now deprecated, please use PowerAuthHttpRequestInterceptor as a replacement.
 */
PA2_DEPRECATED(1.6.0)
@protocol PA2HttpRequestInterceptor <PowerAuthHttpRequestInterceptor>
@end
/**
 The PA2ClientSslValidationStrategy protocol is now deprecated, please use PowerAuthClientSslValidationStrategy as a replacement.
 */
PA2_DEPRECATED(1.6.0)
@protocol PA2ClientSslValidationStrategy <PowerAuthClientSslValidationStrategy>
@end
/**
 PA2OperationTask is now deprecated, please use PowerAuthOperationTask
 */
PA2_DEPRECATED(1.6.0)
@protocol PA2OperationTask <PowerAuthOperationTask>
@end
/**
 The PA2AuthorizationHttpHeader class is deprecated, please use PowerAuthAuthorizationHttpHeader as a replacement.
 */
typedef PowerAuthAuthorizationHttpHeader PA2AuthorizationHttpHeader PA2_DEPRECATED(1.6.0);
/**
 The PA2Otp class is deprecated, please use PowerAuthActivationCode as a replacement.
 */
typedef PowerAuthActivationCode PA2Otp PA2_DEPRECATED(1.6.0);
/**
 The PA2OtpUtil is deprecated, please use PowerAuthActivationCodeUtil as a replacement.
 */
typedef PowerAuthActivationCodeUtil PA2OtpUtil PA2_DEPRECATED(1.6.0);
/**
 PA2ActivationStatus is deprecated, please use PowerAuthActivationStatus as a replacement.
 */
typedef PowerAuthActivationStatus PA2ActivationStatus PA2_DEPRECATED(1.6.0);
/**
 PA2ActivationState is deprecated, please use PowerAuthActivationState as a replacement.
 */
typedef PowerAuthActivationState PA2ActivationState PA2_DEPRECATED(1.6.0);
/**
 PA2ActivationRecoveryData is now deprecated. You can use PowerAuthActivationRecoveryData as a direct replacement.
 */
typedef PowerAuthActivationRecoveryData PA2ActivationRecoveryData PA2_DEPRECATED(1.6.0);
/**
 PA2ActivationResult is deprecated, please use PowerAuthActivationResult as a replacement.
 */
typedef PowerAuthActivationResult PA2ActivationResult PA2_DEPRECATED(1.6.0);

/**
 The PA2CustomHeaderRequestInterceptor is deprecated, please use PowerAuthCustomHeaderRequestInterceptor instead.
 */
typedef PowerAuthCustomHeaderRequestInterceptor PA2CustomHeaderRequestInterceptor PA2_DEPRECATED(1.6.0);
/**
 The PA2BasicHttpAuthenticationRequestInterceptor is deprecated, please use PowerAuthBasicHttpAuthenticationRequestInterceptor instead.
 */
typedef PowerAuthBasicHttpAuthenticationRequestInterceptor PA2BasicHttpAuthenticationRequestInterceptor PA2_DEPRECATED(1.6.0);
/**
 The PowerAuthClientSslNoValidationStrategy is deprecated, please use PA2ClientSslNoValidationStrategy instead.
 */
typedef PowerAuthClientSslNoValidationStrategy PA2ClientSslNoValidationStrategy PA2_DEPRECATED(1.6.0);

// PA2Error*

/** Deprecated, use PowerAuthErrorDomain constant instead. */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorDomain PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorInfoKey_AdditionalInfo constant instead. */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorInfoKey_AdditionalInfo PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorInfoKey_ResponseData constant instead. */
PA2_EXTERN_C NSString * __nonnull const PA2ErrorInfoKey_ResponseData PA2_DEPRECATED(1.6.0);

/** Deprecated, use PowerAuthErrorCode_NetworkError enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeNetworkError PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_SignatureError enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeSignatureError PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_InvalidActivationState enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationState PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_InvalidActivationData enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidActivationData PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_MissingActivation enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeMissingActivation PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_ActivationPending enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeActivationPending PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_BiometryNotAvailable enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryNotAvailable PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_BiometryCancel enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryCancel PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_BiometryFailed enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeBiometryFailed PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_OperationCancelled enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeOperationCancelled PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_Encryption enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeEncryption PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_WrongParameter enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWrongParameter PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_InvalidToken enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeInvalidToken PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_WatchConnectivity enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeWatchConnectivity PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_ProtocolUpgrade enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodeProtocolUpgrade PA2_DEPRECATED(1.6.0);
/** Deprecated, use PowerAuthErrorCode_PendingProtocolUpgrade enum instead. */
PA2_EXTERN_C NSInteger const PA2ErrorCodePendingProtocolUpgrade PA2_DEPRECATED(1.6.0);

/**
 The PA2ErrorResponse is deprecated, please use PowerAuthRestApiErrorResponse instead.
 */
typedef PowerAuthRestApiErrorResponse PA2ErrorResponse PA2_DEPRECATED(1.6.0);
/**
 The PA2Error is deprecated, please use PowerAuthRestApiError instead.
 */
typedef PowerAuthRestApiError PA2Error PA2_DEPRECATED(1.6.0);
/**
 The PA2RestResponseStatus is deprecated, please use PowerAuthRestApiResponseStatus instead.
 */
typedef PowerAuthRestApiResponseStatus PA2RestResponseStatus PA2_DEPRECATED(1.6.0);

// PA2Keychain*

/**
 The PA2KeychainConfiguration class is now deprecated, please use PowerAuthKeychainConfiguration as a replacement.
 */
typedef PowerAuthKeychainConfiguration PA2KeychainConfiguration PA2_DEPRECATED(1.6.0);

PA2_EXTERN_C NSString * __nonnull const PA2Keychain_Initialized PA2_DEPRECATED(1.6.0);
PA2_EXTERN_C NSString * __nonnull const PA2Keychain_Status PA2_DEPRECATED(1.6.0);
PA2_EXTERN_C NSString * __nonnull const PA2Keychain_Possession PA2_DEPRECATED(1.6.0);
PA2_EXTERN_C NSString * __nonnull const PA2Keychain_Biometry PA2_DEPRECATED(1.6.0);
PA2_EXTERN_C NSString * __nonnull const PA2Keychain_TokenStore PA2_DEPRECATED(1.6.0);
PA2_EXTERN_C NSString * __nonnull const PA2KeychainKey_Possession PA2_DEPRECATED(1.6.0);

/**
 The PA2Keychain class is now deprecated, please use PowerAuthKeychain as a replacement.
 */
typedef PowerAuthKeychain PA2Keychain PA2_DEPRECATED(1.6.0);
/**
 The PA2KeychainItemAccess is now deprecated, please use PowerAuthKeychainItemAccess as a replacement.
 */
typedef PowerAuthKeychainItemAccess PA2KeychainItemAccess PA2_DEPRECATED(1.6.0);
/**
 The PA2BiometricAuthenticationInfo is now deprecated, please use PowerAuthBiometricAuthenticationInfo as a replacement.
 */
typedef PowerAuthBiometricAuthenticationInfo PA2BiometricAuthenticationInfo PA2_DEPRECATED(1.6.0);
/**
 The PA2BiometricAuthenticationStatus is now deprecated, please use PowerAuthBiometricAuthenticationStatus as a replacement.
 */
typedef PowerAuthBiometricAuthenticationStatus PA2BiometricAuthenticationStatus PA2_DEPRECATED(1.6.0);
/**
 The PA2BiometricAuthenticationType is now deprecated, please use PowerAuthBiometricAuthenticationType as a replacement.
 */
typedef PowerAuthBiometricAuthenticationType PA2BiometricAuthenticationType PA2_DEPRECATED(1.6.0);
/**
 The PA2KeychainStoreItemResult is now deprecated, please use PowerAuthKeychainStoreItemResult as a replacement.
 */
typedef PowerAuthKeychainStoreItemResult PA2KeychainStoreItemResult PA2_DEPRECATED(1.6.0);

// PA2System

/**
 The PA2System class is now deprecated, please use PowerAuthSystem as a replacement.
 */
typedef PowerAuthSystem PA2System PA2_DEPRECATED(1.6.0);

// PA2Log

/**
 The PA2LogSetEnabled() function is deprecated, please use PowerAuthLogSetEnabled() instead.
 */
PA2_DEPRECATED(1.6.0) PA2_EXTERN_C void PA2LogSetEnabled(BOOL enabled);
/**
 The PA2LogIsEnabled() function is deprecated, please use PowerAuthLogIsEnabled() instead.
 */
PA2_DEPRECATED(1.6.0) PA2_EXTERN_C BOOL PA2LogIsEnabled(void);
/**
 The PA2LogSetVerbose() function is deprecated, please use PowerAuthLogSetVerbose() instead.
 */
PA2_DEPRECATED(1.6.0) PA2_EXTERN_C void PA2LogSetVerbose(BOOL verbose);
/**
 The PA2LogIsVerbose() function is deprecated, please use PowerAuthLogIsVerbose() instead.
 */
PA2_DEPRECATED(1.6.0) PA2_EXTERN_C BOOL PA2LogIsVerbose(void);

// watch

#if defined(PA2_WATCH_SUPPORT)
/**
 The PA2WCSessionManager class is deprecated, please use PowerAuthWCSessionManager instead.
 */
typedef PowerAuthWCSessionManager PA2WCSessionManager PA2_DEPRECATED(1.6.0);
#endif //defined(PA2_WATCH_SUPPORT)
