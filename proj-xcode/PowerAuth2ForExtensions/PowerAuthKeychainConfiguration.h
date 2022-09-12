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

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 Constant specifying the default name of the 'key' used to store flag in NSUserDefaults about initialized PowerAuthSDK instances.
 Used to cleanup the keychain data after the app re-install.
 */
extern NSString * __nonnull const PowerAuthKeychain_Initialized;

/**
 Default name of the keychain service used to store values of the PowerAuthSDK instance session states.
 */
extern NSString * __nonnull const PowerAuthKeychain_Status;

/**
 Default name of the keychain service used to cache possession factor unlock key. This keychain is required because
 enterprise distribution (for example Testflight) changes 'identifierForVendor' used for the key ad-hoc calculation
 on each install - hence the value is cached.
 */
extern NSString * __nonnull const PowerAuthKeychain_Possession;

/**
 Default name of the keychain service used to store values of the PowerAuthSDK instance related biometry keys.
 */
extern NSString * __nonnull const PowerAuthKeychain_Biometry;

/** Default name of the keychain service used to store PowerAuthTokens.
 */
extern NSString * __nonnull const PowerAuthKeychain_TokenStore;

/** Constant specifying the default name of the 'key' used to store the possession key in the possession key keychain.
 */
extern NSString * __nonnull const PowerAuthKeychainKey_Possession;


/**
 Class that is used to provide default (shared) Keychain storage configuration.
 */
@interface PowerAuthKeychainConfiguration : NSObject<NSCopying>

/**
 Access group name used by the PowerAuthSDK keychain instances.
 */
@property (nonatomic, strong, nullable) NSString *keychainAttribute_AccessGroup;

/**
 Suite name used by the NSUserDefaults that check for Keychain data presence.
 
 If the value is not set, `standardUserDefaults` are used. Otherwise, user defaults with given suite name are created.
 In case a developer started using SDK with no suite name specified, the developer is responsible for migrating data
 to the new `NSUserDefaults` before using the SDK with the new suite name.
 */
@property (nonatomic, strong, nullable) NSString *keychainAttribute_UserDefaultsSuiteName;

/**
 Name of the Keychain service used to store statuses for different PowerAuth instances.
 */
@property (nonatomic, strong, nonnull) NSString *keychainInstanceName_Status;

/**
 Name of the Keychain service used to store possession factor related key (one value for all PowerAuthSDK instances).
 */
@property (nonatomic, strong, nonnull) NSString *keychainInstanceName_Possession;

/**
 Name of the Keychain service used to store biometry related keys for different PowerAuth instances.
 */
@property (nonatomic, strong, nonnull) NSString *keychainInstanceName_Biometry;
/**
 Name of the Keychain service used to store content of PowerAuthToken objects.
 */
@property (nonatomic, strong, nonnull) NSString *keychainInstanceName_TokenStore;

/**
 Name of the Keychain key used to store possession fator related key in an associated service.
 */
@property (nonatomic, strong, nonnull) NSString *keychainKey_Possession;

/**
 If set, then the item protected with the biometry is invalidated if fingers are added or removed
 for Touch ID, or if the user re-enrolls for Face ID. The default value is NO (e.g. changing biometry
 in the system doesn't invalidate the entry)
 */
@property (nonatomic, assign) BOOL linkBiometricItemsToCurrentSet;

/**
 If set to YES, then the item protected with the biometry can be accessed also with a device passcode.
 If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is NO, so fallback
 to device's passcode is not enabled.
 */
@property (nonatomic, assign) BOOL allowBiometricAuthenticationFallbackToDevicePasscode;

/**
 If set to YES, then the LAContext object provided by application is invalidated after the use in SDK.
 The default value is YES, so `LAContext` cannot be reused for getting keys protected with biometry.
 */
@property (nonatomic, assign) BOOL invalidateLocalAuthenticationContextAfterUse;

/** Return the shared in stance of a Keychain configuration object.
 
 @return Shared instance of a Keychain configuration.
 */
+ (nonnull instancetype) sharedInstance;

@end
