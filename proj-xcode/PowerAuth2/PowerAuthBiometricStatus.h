/*
 * Copyright 2026 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthKeychain.h>

/// `PowerAuthBiometricStatus` represents the overall availability of biometric
/// authentication in a `PowerAuthSDK` instance.
@interface PowerAuthBiometricStatus : NSObject

/// Default initialization is unavailable.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// If `true`, biometric authentication is fully available and you can call methods
/// that accept a `PowerAuthAuthentication` object configured for biometrics.
///
/// The value is calculated as:
/// ```
/// isBiometricFactorConfigured && biometricAuthenticationStatus == .available
/// ```
@property (nonatomic, readonly) BOOL isAuthenticationWithBiometricsAvailable;

/// Indicates whether the `PowerAuthSDK` instance has a biometric factor configured.
/// If `false`, the user must first set up biometrics via the appropriate registration method.
@property (nonatomic, readonly) BOOL isBiometricFactorConfigured;

/// The current biometric authentication status reported by the system.
@property (nonatomic, readonly) PowerAuthBiometricAuthenticationStatus systemStatus;

/// The type of biometric authentication available on the device (e.g. Face ID or Touch ID).
@property (nonatomic, readonly) PowerAuthBiometricAuthenticationType biometryType;

@end
