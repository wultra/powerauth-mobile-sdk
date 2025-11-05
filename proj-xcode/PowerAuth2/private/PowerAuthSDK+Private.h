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

#import <PowerAuth2/PowerAuthSDK.h>
#import <PowerAuth2/PowerAuthKeychain.h>

#import "PA2GetActivationStatusTask.h"
#import "PA2ProtocolUpgradeTask.h"
#import "PA2KeystoreService.h"
#import "PA2CoreCredentialsResolver.h"
#import "PowerAuthActivationStatus+Private.h"
#import "PowerAuthActivationCode+Private.h"
#import "PowerAuthAuthentication+Private.h"
#import "PowerAuthUserInfo+Private.h"
#import "PowerAuthActivationResult+Private.h"

@import PowerAuthCore;

// Exposing several private interfaces
@interface PowerAuthSDK (Private) <PA2GetActivationStatusTaskDelegate, PA2ProtocolUpgradeTaskDelegate, PA2CoreCredentialsResolver>
/**
 Contains instance identifier
 */
@property (nonatomic, strong, readonly) NSString * privateInstanceId;
/**
 Contains instnace of keystore service.
 */
@property (nonatomic, strong, readonly) PA2KeystoreService * keystoreService;

/**
 Update last fetched user info.
 */
- (void) setLastFetchedUserInfo:(PowerAuthUserInfo*)lastFetchedUserInfo;

@end

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#import "PA2WCSessionDataHandler.h"
// Declaration required by watchSDK integration (see PowerAuthSDK+WatchSupport.m)
@interface PowerAuthSDK (WatchSupportPrivate) <PA2WCSessionDataHandler>
@end
// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

// Reveal private property that helps convert LAContext or prompt into PowerAuthKeychainAuthentication.
@interface PowerAuthAuthentication (KeychainAuth)
@property (nonatomic, strong, readonly) PowerAuthKeychainAuthentication * keychainAuthentication;
@end

@interface PowerAuthBiometricConfiguration (PrivateSupport)
// Reveal private constructor that allows create PowerAuthBiometricConfiguration from PowerAuthKeychainConfiguration
// PA2_DEPRECATED(2.0.0)
- (instancetype) initWithKeychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration;
// Reveal private readonly property that helps distinguish between "current" or "any set" biometric access.
@property (nonatomic, readonly) PowerAuthKeychainItemAccess biometricItemAccess;
@end

@interface PowerAuthVaultEncryptionKey (Private)
- (instancetype) initWithCoreData:(PowerAuthCoreData*)coreData
                            keyId:(PowerAuthVaultEncryptionKeyId)keyId
                            index:(UInt64)index
                             base:(BOOL)base;
@end

@interface PowerAuthDevicePublicKeyData (Private)
- (instancetype) initWithCoreDevicePublicKeyData:(PowerAuthCoreDevicePublicKeyData*)keyData;
@end
