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

#import <PowerAuth2/PowerAuthMacros.h>

/**
 The `PowerAuthBiometricConfiguration` object contains biometric configuration for `PowerAuthSDK` class.
 */
@interface PowerAuthBiometricConfiguration : NSObject<NSCopying>

/**
 If set to `true`, then the biometric factor key is invalidated if fingers are added or removed
 for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing biometry
 in the system doesn't invalidate the factor key)
 */
@property (nonatomic, assign) BOOL invalidateBiometricFactorAfterChange;

/**
 If set to `true`, then the item protected with the biometry can be accessed also with a device passcode.
 If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is NO, so fallback
 to device's passcode is not enabled.
 */
@property (nonatomic, assign) BOOL allowFallbackToDevicePasscode;

/**
 If set to YES, then the `LAContext` object provided by application is invalidated after the use in SDK.
 The default value is YES, so `LAContext` cannot be reused for getting keys protected with biometry.
 */
@property (nonatomic, assign) BOOL invalidateLocalAuthenticationContextAfterUse;

@end
