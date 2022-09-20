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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import "PowerAuthKeychainConfiguration.h"
#import "PA2PrivateConstants.h"

NSString *const PowerAuthKeychain_Initialized       = PA2Def_PowerAuthKeychain_Initialized;
NSString *const PowerAuthKeychain_Status            = PA2Def_PowerAuthKeychain_Status;
NSString *const PowerAuthKeychain_Possession        = PA2Def_PowerAuthKeychain_Possession;
NSString *const PowerAuthKeychain_Biometry          = PA2Def_PowerAuthKeychain_Biometry;
NSString *const PowerAuthKeychain_TokenStore        = PA2Def_PowerAuthKeychain_TokenStore;
NSString *const PowerAuthKeychainKey_Possession     = PA2Def_PowerAuthKeychainKey_Possession;

@implementation PowerAuthKeychainConfiguration

- (instancetype)init
{
    self = [super init];
    if (self) {
        // Initialize default value for keychain service keys
        _keychainInstanceName_Status        = PowerAuthKeychain_Status;
        _keychainInstanceName_Possession    = PowerAuthKeychain_Possession;
        _keychainInstanceName_Biometry      = PowerAuthKeychain_Biometry;
        _keychainInstanceName_TokenStore    = PowerAuthKeychain_TokenStore;
        
        // Initialize default values for keychain service record item keys
        _keychainKey_Possession             = PowerAuthKeychainKey_Possession;
        // Default config for biometry protected items
        _linkBiometricItemsToCurrentSet = NO;
        _allowBiometricAuthenticationFallbackToDevicePasscode = NO;
        _invalidateLocalAuthenticationContextAfterUse = YES;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone
{
    PowerAuthKeychainConfiguration * c = [[self.class allocWithZone:zone] init];
    if (c) {
        c->_keychainAttribute_AccessGroup = _keychainAttribute_AccessGroup;
        c->_keychainAttribute_UserDefaultsSuiteName = _keychainAttribute_UserDefaultsSuiteName;
        c->_keychainInstanceName_Status = _keychainInstanceName_Status;
        c->_keychainInstanceName_Possession = _keychainInstanceName_Possession;
        c->_keychainInstanceName_Biometry = _keychainInstanceName_Biometry;
        c->_keychainInstanceName_TokenStore = _keychainInstanceName_TokenStore;
        c->_keychainKey_Possession = _keychainKey_Possession;
        c->_linkBiometricItemsToCurrentSet = _linkBiometricItemsToCurrentSet;
        c->_allowBiometricAuthenticationFallbackToDevicePasscode = _allowBiometricAuthenticationFallbackToDevicePasscode;
        c->_invalidateLocalAuthenticationContextAfterUse = _invalidateLocalAuthenticationContextAfterUse;
    }
    return c;
}

+ (instancetype)sharedInstance
{
    static dispatch_once_t onceToken;
    static PowerAuthKeychainConfiguration *inst;
    dispatch_once(&onceToken, ^{
        inst = [[PowerAuthKeychainConfiguration alloc] init];
    });
    return inst;
}

@end
