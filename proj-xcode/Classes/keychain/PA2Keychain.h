/**
 * Copyright 2016 Wultra s.r.o.
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

#import "PA2KeychainConfiguration.h"
#import "PA2Macros.h"

/**
 Enum encapsulating possible Keychain query result.
 */
typedef NS_ENUM(int, PA2KeychainStoreItemResult) {
	PA2KeychainStoreItemResult_Ok = 0,
	PA2KeychainStoreItemResult_BiometryNotAvailable = 1,
	PA2KeychainStoreItemResult_Duplicate = 2,
	PA2KeychainStoreItemResult_NotFound = 3,
	PA2KeychainStoreItemResult_Other = 4,
};

/**
 Enum encapsulating supported biometric authentication types.
 */
typedef NS_ENUM(int, PA2BiometricAuthenticationType) {
	/**
	 Biometric authentication is not supported on the current system.
	 */
	PA2BiometricAuthenticationType_None,
	/**
	 Touch ID is supported on the current system.
	 */
	PA2BiometricAuthenticationType_TouchID,
	/**
	 Face ID is supported on the current system.
	 */
	PA2BiometricAuthenticationType_FaceID,
};

/**
 Enum encapsulating status of biometric authentication on the system.
 */
typedef NS_ENUM(int, PA2BiometricAuthenticationStatus) {
	/**
	 Biometric authentication is not present on the system
	 */
	PA2BiometricAuthenticationStatus_NotSupported,
	/**
	 Biometric authentication is available on the system, but for an unknown
	 reason is not available right now. This may happen on iOS 11+, when an
	 unknown error is returned from `LAContext.canEvaluatePolicy()`.
	 */
	PA2BiometricAuthenticationStatus_NotAvailable,
	/**
	 Biometric authentication is supported, but not enrolled on the system.
	 */
	PA2BiometricAuthenticationStatus_NotEnrolled,
	/**
	 Biometric authentication is supported, but too many failed attempts caused its lockout.
	 User has to authenticate with the password or passcode.
	 */
	PA2BiometricAuthenticationStatus_Lockout,
	/**
	 Biometric authentication is supported and can be evaluated on the system.
	 */
	PA2BiometricAuthenticationStatus_Available,
};

/**
 The PA2BiometricAuthenticationInfo structure contains information about
 supported type of biometry and its current status on the system.
 */
typedef struct PA2BiometricAuthenticationInfo {
	/**
	 Current status of supported biometry on the system.
	 */
	PA2BiometricAuthenticationStatus currentStatus;
	/**
	 Type of supported biometric authentication on the system.
	 */
	PA2BiometricAuthenticationType biometryType;
	
} PA2BiometricAuthenticationInfo;


/**
 Enum encapsulating type of additional protection of item stored in the keychain.
 */
typedef NS_ENUM(int, PA2KeychainItemAccess) {
	/**
	 No additional authentication is required to access the item.
	 */
	PA2KeychainItemAccess_None,
	/**
	 Constraint to access an item with Touch ID for currently enrolled fingers,
	 or from Face ID with the currently enrolled user.
	 */
	PA2KeychainItemAccess_CurrentBiometricSet,
	/**
	 Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
	 */
	PA2KeychainItemAccess_AnyBiometricSet,
};

/** Simple wrapper on top of an iOS Keychain.
 */
@interface PA2Keychain : NSObject

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

/** Store data for given key in the Keychain synchronously. If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @return Operation result.
 */
- (PA2KeychainStoreItemResult) addValue:(nonnull NSData*)data
								 forKey:(nonnull NSString*)key;

/**
 Store data for given key in the Keychain asynchronously, return the result in a callback. If a value for given key exists,
 'PA2KeychainStoreItemResult_Duplicate' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
		   forKey:(nonnull NSString*)key
	   completion:(nonnull void(^)(PA2KeychainStoreItemResult status))completion;

/**
 Store data for given key in the Keychain synchronously.

 If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned. This method let's you optionally
 protect the record with biometry on iOS 9.0 and newer. When iOS version is lower than 9.0 and biometry is requested,
 this method returns 'PA2KeychainStoreItemResult_BiometryNotAvailable' response code.

 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param access Restrict access to the item.
 @return Operation result.
*/
- (PA2KeychainStoreItemResult) addValue:(nonnull NSData*)data
								 forKey:(nonnull NSString*)key
								 access:(PA2KeychainItemAccess)access;

/**
 Store data for given key in the Keychain asynchronously, return the result in a callback.
 
 If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned. This method let's you optionally
 protect the record with biometry on iOS 9.0 and newer. When iOS version is lower than 9.0 and biometry is requested,
 this method returns 'PA2KeychainStoreItemResult_BiometryNotAvailable' response code.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param access Restrict access to the item.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
		   forKey:(nonnull NSString*)key
		   access:(PA2KeychainItemAccess)access
	   completion:(nonnull void(^)(PA2KeychainStoreItemResult status))completion;

/**
 Updates data for given key in the Keychain synchronously. If a value for given key does not exist, 'PA2KeychainStoreItemResult_NotFound' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @return Operation result.
 */
- (PA2KeychainStoreItemResult) updateValue:(nonnull NSData*)data
									forKey:(nonnull NSString*)key;

/**
 Updates data for given key in the Keychain asynchronously, returns the result in a callback. If a value for given key does not exist,
 'PA2KeychainStoreItemResult_NotFound' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param completion Callback with the operation result.
 */
- (void) updateValue:(nonnull NSData*)data
			  forKey:(nonnull NSString*)key
		  completion:(nonnull void(^)(PA2KeychainStoreItemResult status))completion;

/** Removes a record with a specified key synchronously.
 
 @param key Key of the record to be deleted.
 @returns Returns YES if an item was deleted, NO otherwise.
 */
- (BOOL) deleteDataForKey:(nonnull NSString*)key;

/** Removes a record with a specified key asynchronously, returns the result in a callback.
 
 @param key Key of the record to be deleted.
 @param completion Callback with the operation result - YES if the record was deleted, NO otherwise.
 */
- (void) deleteDataForKey:(nonnull NSString*)key
			   completion:(nonnull void(^)(BOOL deleted))completion;

/**
 Delete all data that are stored for all keychains.
 */
+ (void) deleteAllData;

/**
 Delete all data that are stored in this keychain.
 */
- (void) deleteAllData;

/**
 Retrieve the data for given key in the Keychain synchronously, in case record requires Touch ID, use given prompt in the dialog.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @param prompt Prompt displayed to user when requesting record with Touch ID.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString *)key status:(nullable OSStatus *)status prompt:(nullable NSString*)prompt;

/**
 Retrieve the data for given key in the Keychain synchronously.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString*)key status:(nullable OSStatus *)status;

/**
 Retrieve the data for given key in the Keychain asynchronously, return result in a callbacl.
 
 @param key Key for which to retrieve the value.
 @param prompt Prompt displayed to user when requesting record protected with biometry.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
			 prompt:(nullable NSString*)prompt
		 completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion;

/**
 Retrieve the data for given key in the Keychain asynchronously, return result in a callback.
 
 @param key Key for which to retrieve the value.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
		 completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion;

/**
 Checks if a value exists for given key in Keychain synchronously.
 
 @param key Key for which to check the value presence.
 @return Returns YES in case record for given key was found, NO otherwise.
 */
- (BOOL) containsDataForKey:(nonnull NSString*)key;

/**
 Checks if a value exists for given key in Keychain asynchronously, return result in a callback.
 
 @param key Key for which to check the value presence.
 @param completion Callback with the information about value presence.
 */
- (void) containsDataForKey:(nonnull NSString*)key
				 completion:(nonnull void(^)(BOOL containsValue))completion;

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

 @param prompt Prompt displayed in case that Touch ID authentication is required.
 @param status Status that was returned when obtaining keychain item.
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items,
         operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItemsWithPrompt:(nullable NSString*)prompt withStatus: (nullable OSStatus *)status;

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
@property (class, readonly) PA2BiometricAuthenticationType supportedBiometricAuthentication;

/**
 Static property that returns full information about biometry on the system. The resturned structure contains
 information about supported type (Touch ID or Face ID) and also actual biometry status (N/A, not enrolled, etc..).
 
 @return Structure containing full information about current supported biometry and its status on the system.
 */
@property (class, readonly) PA2BiometricAuthenticationInfo biometricAuthenticationInfo;

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
