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

#import <PowerAuth2ForExtensions/PowerAuthKeychainConfiguration.h>
#import <PowerAuth2ForExtensions/PowerAuthKeychainAuthentication.h>

/**
 Enum encapsulating possible Keychain query result.
 */
typedef NS_ENUM(NSInteger, PowerAuthKeychainStoreItemResult) {
    PowerAuthKeychainStoreItemResult_Ok = 0,
    PowerAuthKeychainStoreItemResult_BiometryNotAvailable = 1,
    PowerAuthKeychainStoreItemResult_Duplicate = 2,
    PowerAuthKeychainStoreItemResult_NotFound = 3,
    PowerAuthKeychainStoreItemResult_Other = 4,
};

/**
 Enum encapsulating supported biometric authentication types.
 */
typedef NS_ENUM(NSInteger, PowerAuthBiometricAuthenticationType) {
    /**
     Biometric authentication is not supported on the current system.
     */
    PowerAuthBiometricAuthenticationType_None,
    /**
     Touch ID is supported on the current system.
     */
    PowerAuthBiometricAuthenticationType_TouchID,
    /**
     Face ID is supported on the current system.
     */
    PowerAuthBiometricAuthenticationType_FaceID,
};

/**
 Enum encapsulating status of biometric authentication on the system.
 */
typedef NS_ENUM(NSInteger, PowerAuthBiometricAuthenticationStatus) {
    /**
     Biometric authentication is not present on the system
     */
    PowerAuthBiometricAuthenticationStatus_NotSupported,
    /**
     Biometric authentication is available on the system, but for an unknown
     reason is not available right now. This may happen on iOS 11+, when an
     unknown error is returned from `LAContext.canEvaluatePolicy()`.
     */
    PowerAuthBiometricAuthenticationStatus_NotAvailable,
    /**
     Biometric authentication is supported, but not enrolled on the system.
     */
    PowerAuthBiometricAuthenticationStatus_NotEnrolled,
    /**
     Biometric authentication is supported, but too many failed attempts caused its lockout.
     User has to authenticate with the password or passcode.
     */
    PowerAuthBiometricAuthenticationStatus_Lockout,
    /**
     Biometric authentication is supported and can be evaluated on the system.
     */
    PowerAuthBiometricAuthenticationStatus_Available,
};

/**
 The PowerAuthBiometricAuthenticationInfo structure contains information about
 supported type of biometry and its current status on the system.
 */
typedef struct PowerAuthBiometricAuthenticationInfo {
    /**
     Current status of supported biometry on the system.
     */
    PowerAuthBiometricAuthenticationStatus currentStatus;
    /**
     Type of supported biometric authentication on the system.
     */
    PowerAuthBiometricAuthenticationType biometryType;
    
} PowerAuthBiometricAuthenticationInfo;


/**
 Enum encapsulating type of additional protection of item stored in the keychain.
 */
typedef NS_ENUM(NSInteger, PowerAuthKeychainItemAccess) {
    /**
     No additional authentication is required to access the item.
     */
    PowerAuthKeychainItemAccess_None,
    /**
     Constraint to access an item with Touch ID for currently enrolled fingers,
     or from Face ID with the currently enrolled user.
     */
    PowerAuthKeychainItemAccess_CurrentBiometricSet,
    /**
     Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
     */
    PowerAuthKeychainItemAccess_AnyBiometricSet,
    /**
     Constraint to access an item with any enrolled biometry or device's passcode.
     */
    PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode,
};

/** Simple wrapper on top of an iOS Keychain.
 */
@interface PowerAuthKeychain : NSObject

/**
 Identifier of the service.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * identifier;
/**
 Optional access group for the Keychain Sharing.
 */
@property (nonatomic, strong, nullable, readonly) NSString * accessGroup;

/**
 Init a new keychain instance for a service with given identifier.

 @param identifier Identifier of the service.
 @return New instance of a PA2Keychain.
 */
- (nonnull instancetype) initWithIdentifier:(nonnull NSString*)identifier;

/**
 Init a new keychain instance for a service with given identifier.
 
 @param identifier Identifier of the service.
 @param accessGroup Access group for the Keychain Sharing.
 @return New instance of a PA2Keychain.
 */
- (nonnull instancetype) initWithIdentifier:(nonnull NSString*)identifier accessGroup:(nullable NSString*)accessGroup;

/** Store data for given key in the Keychain synchronously. If a value for given key exists, 'PowerAuthKeychainStoreItemResult_Duplicate' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @return Operation result.
 */
- (PowerAuthKeychainStoreItemResult) addValue:(nonnull NSData*)data
                                       forKey:(nonnull NSString*)key;

/**
 Store data for given key in the Keychain synchronously.

 If a value for given key exists, 'PowerAuthKeychainStoreItemResult_Duplicate' is returned. This method let's you optionally
 protect the record with biometry on iOS 9.0 and newer. When iOS version is lower than 9.0 and biometry is requested,
 this method returns 'PowerAuthKeychainStoreItemResult_BiometryNotAvailable' response code.

 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param access Restrict access to the item.
 @return Operation result.
*/
- (PowerAuthKeychainStoreItemResult) addValue:(nonnull NSData*)data
                                       forKey:(nonnull NSString*)key
                                       access:(PowerAuthKeychainItemAccess)access;

/**
 Updates data for given key in the Keychain synchronously. If a value for given key does not exist, 'PowerAuthKeychainStoreItemResult_NotFound' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @return Operation result.
 */
- (PowerAuthKeychainStoreItemResult) updateValue:(nonnull NSData*)data
                                          forKey:(nonnull NSString*)key;

/** Removes a record with a specified key synchronously.
 
 @param key Key of the record to be deleted.
 @returns Returns YES if an item was deleted, NO otherwise.
 */
- (BOOL) deleteDataForKey:(nonnull NSString*)key;

/**
 Delete all data that are stored for all keychains.
 */
+ (void) deleteAllData;

/**
 Delete all data that are stored in this keychain.
 */
- (void) deleteAllData;

/**
 Retrieve the data for given key in the Keychain synchronously, in case record requires biometry, use given authentication object.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @param authentication Keychain authentication in case that keychain item is protected with biometry.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString *)key
                         status:(nullable OSStatus *)status
                 authentication:(nullable PowerAuthKeychainAuthentication*)authentication;

/**
 Retrieve the data for given key in the Keychain synchronously.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString*)key
                         status:(nullable OSStatus *)status;

/**
 Checks if a value exists for given key in Keychain synchronously.
 
 @param key Key for which to check the value presence.
 @return Returns YES in case record for given key was found, NO otherwise.
 */
- (BOOL) containsDataForKey:(nonnull NSString*)key;

/**
 Return all items that are stored in this Keychain.
 
 If some of the items are protected by Touch or Face ID, then biometric authentication is required.
 
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items,
         operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItems;

/**
 Return all items that are stored in this Keychain.

 If some of the items are protected by Touch or Face ID, then biometric authentication is required and prompt message
 specified as a parameter is used.

 @param authentication Keychain authentication in case that items are protected with biometry.
 @param status Status that was returned when obtaining keychain item.
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items,
         operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItemsWithAuthentication:(nullable PowerAuthKeychainAuthentication*)authentication
                                           withStatus:(nullable OSStatus *)status;
/**
 Convenience static property that checks if Touch ID or Face ID can be used on the current system.
 
 Note that the property contains "NO" also if biometry is not enrolled or if it has been locked down. To distinguish between
 an availability and lockdown you can use `biometricAuthenticationInfo` static property.
 
 @return YES if biometry can be used (iOS 9.0+), NO otherwise. On watchOS or iOS App Extensions always returns NO.
 */
@property (class, readonly) BOOL canUseBiometricAuthentication;

/**
 Convenience static property that returns supported biometry on the current system.
 
 Note that the property contains "None" also if biometry is not enrolled or if it has been locked down. To distinguish between
 an availability and lockdown you can use `biometricAuthenticationInfo` static property.
 
 @return Type of supported biometric authentication on current system. On watchOS or iOS App Extensions always returns None.
 */
@property (class, readonly) PowerAuthBiometricAuthenticationType supportedBiometricAuthentication;

/**
 Static property that returns full information about biometry on the system. The resturned structure contains
 information about supported type (Touch ID or Face ID) and also actual biometry status (N/A, not enrolled, etc..).
 
 @return Structure containing full information about current supported biometry and its status on the system.
 */
@property (class, readonly) PowerAuthBiometricAuthenticationInfo biometricAuthenticationInfo;

/**
 Try lock the global mutex and execute the provided block, but only if the lock is acquired. The mutex is released
 immediately after the block execution.
 
 The function is useful in case that PowerAuth SDK needs to guarantee that only one biometric authentication request
 is executed at the same time. It's forbidden to throw an exception from the block.
 
 Note that the method is not implemented on watchOS or for iOS App Extensions SDK.
 
 @return YES in case that the provided block has been executed, otherwise NO
 */
+ (BOOL) tryLockBiometryAndExecuteBlock:(void (^_Nonnull)(void))block;

@end


// MARK: - Deprecated

@interface PowerAuthKeychain (Deprecated)
/**
 Store data for given key in the Keychain asynchronously, return the result in a callback. If a value for given key exists,
 'PowerAuthKeychainStoreItemResult_Duplicate' is returned.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
           forKey:(nonnull NSString*)key
       completion:(nonnull void(^)(PowerAuthKeychainStoreItemResult status))completion PA2_DEPRECATED(1.7.0);

/**
 Store data for given key in the Keychain asynchronously, return the result in a callback.
 
 If a value for given key exists, 'PowerAuthKeychainStoreItemResult_Duplicate' is returned. This method let's you optionally
 protect the record with biometry on iOS 9.0 and newer. When iOS version is lower than 9.0 and biometry is requested,
 this method returns 'PowerAuthKeychainStoreItemResult_BiometryNotAvailable' response code.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param access Restrict access to the item.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
           forKey:(nonnull NSString*)key
           access:(PowerAuthKeychainItemAccess)access
       completion:(nonnull void(^)(PowerAuthKeychainStoreItemResult status))completion PA2_DEPRECATED(1.7.0);

/**
 Updates data for given key in the Keychain asynchronously, returns the result in a callback. If a value for given key does not exist,
 'PowerAuthKeychainStoreItemResult_NotFound' is returned.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param completion Callback with the operation result.
 */
- (void) updateValue:(nonnull NSData*)data
              forKey:(nonnull NSString*)key
          completion:(nonnull void(^)(PowerAuthKeychainStoreItemResult status))completion PA2_DEPRECATED(1.7.0);

/** Removes a record with a specified key asynchronously, returns the result in a callback.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param key Key of the record to be deleted.
 @param completion Callback with the operation result - YES if the record was deleted, NO otherwise.
 */
- (void) deleteDataForKey:(nonnull NSString*)key
               completion:(nonnull void(^)(BOOL deleted))completion PA2_DEPRECATED(1.7.0);

/**
 Retrieve the data for given key in the Keychain synchronously, in case record requires Touch ID, use given prompt in the dialog.
 
 This method is deprecated and you can use variant with PowerAuthKeychainAuthentication as a replacement.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @param prompt Prompt displayed to user when requesting record with Touch ID.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString *)key
                         status:(nullable OSStatus *)status
                         prompt:(nullable NSString*)prompt PA2_DEPRECATED(1.7.0);

/**
 Retrieve the data for given key in the Keychain asynchronously, return result in a callback.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param key Key for which to retrieve the value.
 @param prompt Prompt displayed to user when requesting record protected with biometry.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
             prompt:(nullable NSString*)prompt
         completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion PA2_DEPRECATED(1.7.0);

/**
 Retrieve the data for given key in the Keychain asynchronously, return result in a callback.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param key Key for which to retrieve the value.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
         completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion PA2_DEPRECATED(1.7.0);

/**
 Checks if a value exists for given key in Keychain asynchronously, return result in a callback.
 
 This method is deprecated, please use synchronous variant as a replacement.
 
 @param key Key for which to check the value presence.
 @param completion Callback with the information about value presence.
 */
- (void) containsDataForKey:(nonnull NSString*)key
                 completion:(nonnull void(^)(BOOL containsValue))completion PA2_DEPRECATED(1.7.0);

/**
 Return all items that are stored in this Keychain.

 If some of the items are protected by Touch or Face ID, then biometric authentication is required and prompt message
 specified as a parameter is used.
 
 This method is deprecated and you can use variant with PowerAuthKeychainAuthentication as a replacement.

 @param prompt Prompt displayed in case that Touch ID authentication is required.
 @param status Status that was returned when obtaining keychain item.
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items,
         operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItemsWithPrompt:(nullable NSString*)prompt
                                   withStatus:(nullable OSStatus *)status PA2_DEPRECATED(1.7.0);

@end
