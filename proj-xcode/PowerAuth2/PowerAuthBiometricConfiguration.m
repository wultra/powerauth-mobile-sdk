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

#import "PowerAuthBiometricConfiguration.h"
#import "PowerAuthKeychainConfiguration.h"
#import "PowerAuthKeychain.h"

@implementation PowerAuthBiometricConfiguration

- (instancetype) init
{
    self = [super init];
    if (self) {
        _invalidateBiometricFactorAfterChange = NO;
        _allowFallbackToDevicePasscode = NO;
        _invalidateLocalAuthenticationContextAfterUse = YES;
    }
    return self;
}

- (id) copyWithZone:(NSZone *)zone
{
    PowerAuthBiometricConfiguration * c = [[self.class allocWithZone:zone] init];
    if (c) {
        c->_invalidateBiometricFactorAfterChange = _invalidateBiometricFactorAfterChange;
        c->_allowFallbackToDevicePasscode = _allowFallbackToDevicePasscode;
        c->_invalidateLocalAuthenticationContextAfterUse = _invalidateLocalAuthenticationContextAfterUse;
    }
    return c;
}

- (PowerAuthKeychainItemAccess) biometricItemAccess
{
    if (self.allowFallbackToDevicePasscode) {
        return PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode;
    } else if (self.invalidateBiometricFactorAfterChange) {
        return PowerAuthKeychainItemAccess_CurrentBiometricSet;
    } else {
        return PowerAuthKeychainItemAccess_AnyBiometricSet;
    }
}


// Compatibility due to PA2_DEPRECATED(1.10.0), remove constructor in 2.0.0

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
- (instancetype) initWithKeychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration
{
    self = [super init];
    if (self) {
        _invalidateBiometricFactorAfterChange = keychainConfiguration.linkBiometricItemsToCurrentSet;
        _allowFallbackToDevicePasscode = keychainConfiguration.allowBiometricAuthenticationFallbackToDevicePasscode;
        _invalidateLocalAuthenticationContextAfterUse = keychainConfiguration.invalidateLocalAuthenticationContextAfterUse;
    }
    return self;
}
#pragma clang diagnostic pop

@end
