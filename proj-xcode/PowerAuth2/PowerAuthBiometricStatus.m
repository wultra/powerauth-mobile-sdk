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

#import "PowerAuthBiometricStatus.h"

@implementation PowerAuthBiometricStatus

- (instancetype) initWithBiometricInfo:(PowerAuthBiometricAuthenticationInfo)biometricInfo
                             factorSet:(BOOL)factorSet
{
    self = [super init];
    if (self) {
        BOOL statusAvailable = biometricInfo.currentStatus == PowerAuthBiometricAuthenticationStatus_Available;
        _systemStatus = biometricInfo.currentStatus;
        _biometryType = biometricInfo.biometryType;
        _isBiometricFactorConfigured = factorSet;
        _isAuthenticationWithBiometricsAvailable = factorSet && statusAvailable;
    }
    return self;
}

@end
