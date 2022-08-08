/**
 * Copyright 2022 Wultra s.r.o.
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

#import <PowerAuth2ForExtensions/PowerAuthExtensionSDK.h>
#import <PowerAuth2ForExtensions/PowerAuthKeychain.h>
#import <PowerAuth2ForExtensions/PowerAuthLog.h>

#import "PA2PrivateTokenKeychainStore.h"
#import "PA2SessionStatusDataReader.h"

@interface PowerAuthExtensionSDK (TokenLock) <PA2TokenDataLock>
@end

@implementation PowerAuthExtensionSDK
{
    PowerAuthConfiguration * _configuration;
    id<NSLocking> _lock;
    PowerAuthKeychain * _statusKeychain;
    NSUserDefaults * _userDefaults;
}

#pragma mark - Initialization

- (instancetype) initWithConfiguration:(PowerAuthConfiguration *)configuration
                 keychainConfiguration:(PowerAuthKeychainConfiguration *)keychainConfiguration
{
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _lock = [[NSRecursiveLock alloc] init];
        
        // Create status keychain
        _statusKeychain = [[PowerAuthKeychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_Status
                                                            accessGroup:keychainConfiguration.keychainAttribute_AccessGroup];
        // Create token store keychain
        PowerAuthKeychain * tokenStoreKeychain = [[PowerAuthKeychain alloc] initWithIdentifier:keychainConfiguration.keychainInstanceName_TokenStore
                                                                                   accessGroup:keychainConfiguration.keychainAttribute_AccessGroup];
        // ...and finally, create a token store
        PA2PrivateTokenKeychainStore * tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:_configuration
                                                                                                       keychain:tokenStoreKeychain
                                                                                                 statusProvider:self
                                                                                                 remoteProvider:nil
                                                                                                       dataLock:self
                                                                                                      localLock:_lock];
        // For extensions, it's better to always access token data directly from keychain
        tokenStore.allowInMemoryCache = NO;
        _tokenStore = tokenStore;
        if (keychainConfiguration.keychainAttribute_UserDefaultsSuiteName) {
            _userDefaults = [[NSUserDefaults alloc] initWithSuiteName:keychainConfiguration.keychainAttribute_UserDefaultsSuiteName];
        } else {
            _userDefaults = nil;
        }
    }
    return self;
}

#pragma mark - Getters

- (PowerAuthConfiguration*) configuration
{
    return [_configuration copy];
}

#pragma mark - PA2SessionStatus implementation

- (BOOL) canStartActivation
{
    return NO;
}

- (BOOL) hasPendingActivation
{
    return NO;
}

- (BOOL) hasValidActivation
{
    return self.activationIdentifier != nil;
}

- (BOOL) hasPendingProtocolUpgrade
{
    return NO;
}

- (BOOL) hasProtocolUpgradeAvailable
{
    return NO;
}

- (NSString*) activationIdentifier
{
    if (_userDefaults) {
        if (NO == [_userDefaults boolForKey:PowerAuthKeychain_Initialized]) {
            return nil;    // Missing keychain initialization flag, stored in user defaults
        }
    } else {
        // The extension can work with this configuration, but it may lead to possible false positive
        // validation detections. The problematic scenario is:
        //    1. application has a valid activation
        //    2. user uninstall application (the session status is still in keychain)
        //    3. user install application again
        //    4. user enables extension without running application for first time
        // The result is that this function may return YES but the stored activation is not valid.
        PowerAuthLog(@"WARNING: Missing setup for PowerAuthKeychain.keychainAttribute_UserDefaultsSuiteName.");
    }
    // Retrieve & investigate data stored in keychain
    NSData *sessionData = [_statusKeychain dataForKey:_configuration.instanceId status:nil];
    return PA2SessionStatusDataReader_GetActivationId(sessionData);
}

#pragma mark - PA2TokenDataLock implementation

- (BOOL) lockTokenStore
{
    [_lock lock];
    return NO;
}

- (void) unlockTokenStore:(BOOL)contentModified
{
    [_lock unlock];
}

@end
