/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import <Foundation/Foundation.h>

/** Constant specifying the default name of the 'key' used to store flag in NSUserDefaults about initialized PowerAuthSDK instances. Used to cleanup the keychain data after the app re-install.
 */
extern NSString * __nonnull const PA2Keychain_Initialized;

/** Default name of the keychain service used to store values of the PowerAuthSDK instance session states.
 */
extern NSString * __nonnull const PA2Keychain_Status;

/** Default name of the keychain service used to cache possession factor unlock key. This keychain is required because enterprise distribution (for example Testflight) changes 'identifierForVendor' used for the key ad-hoc calculation on each install - hence the value is cached.
 */
extern NSString * __nonnull const PA2Keychain_Possession;

/** Default name of the keychain service used to store values of the PowerAuthSDK instance related biometry keys.
 */
extern NSString * __nonnull const PA2Keychain_Biometry;

/** Default name of the keychain service used to store PowerAuthTokens.
 */
extern NSString * __nonnull const PA2Keychain_TokenStore;

/** Constant specifying the default name of the 'key' used to store the possession key in the possession key keychain.
 */
extern NSString * __nonnull const PA2KeychainKey_Possession;

/** Enum encapsulating possible Keychain query result.
 */
typedef NS_ENUM(int, PA2KeychainStoreItemResult) {
	PA2KeychainStoreItemResult_Ok = 0,
	PA2KeychainStoreItemResult_TouchIDNotAvailable = 1,
	PA2KeychainStoreItemResult_Duplicate = 2,
	PA2KeychainStoreItemResult_NotFound = 3,
	PA2KeychainStoreItemResult_Other = 4
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

/** Init a new keychain instance for a service with given identifier.

 @param identifier Identifier of the service.
 @return New instance of a PA2Keychain.
 */
- (nonnull instancetype) initWithIdentifier:(nonnull NSString*)identifier;

/** Init a new keychain instance for a service with given identifier.
 
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

/** Store data for given key in the Keychain asynchronously, return the result in a callback. If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
		   forKey:(nonnull NSString*)key
	   completion:(nonnull void(^)(PA2KeychainStoreItemResult status))completion;

/** Store data for given key in the Keychain synchronously.
 
 If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned. This method let's you optionally protect the record with Touch ID on iOS 9.0 and newer. When iOS version is lower than 9.0 nad Touch ID is requested, this method returns 'PA2KeychainStoreItemResult_TouchIDNotAvailable' response code.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param useTouchId If set to true, the record will be protected using Touch ID. Uses 'kSecAccessControlTouchIDAny' for record storage.
 @return Operation result.
 */
- (PA2KeychainStoreItemResult) addValue:(nonnull NSData*)data
								 forKey:(nonnull NSString*)key
							 useTouchId:(BOOL)useTouchId;

/** Store data for given key in the Keychain asynchronously, return the result in a callback.
 
 If a value for given key exists, 'PA2KeychainStoreItemResult_Duplicate' is returned. This method let's you optionally protect the record with Touch ID on iOS 9.0 and newer. When iOS version is lower than 9.0 nad Touch ID is requested, this method returns 'PA2KeychainStoreItemResult_TouchIDNotAvailable' response code.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @param useTouchId If set to true, the record will be protected using Touch ID. Uses 'kSecAccessControlTouchIDAny' for record storage.
 @param completion Callback with the operation result.
 */
- (void) addValue:(nonnull NSData*)data
		   forKey:(nonnull NSString*)key
	   useTouchId:(BOOL)useTouchId
	   completion:(nonnull void(^)(PA2KeychainStoreItemResult status))completion;

/** Updates data for given key in the Keychain synchronously. If a value for given key does not exist, 'PA2KeychainStoreItemResult_NotFound' is returned.
 
 @param data Secret data to be stored.
 @param key Key to use for data storage.
 @return Operation result.
 */
- (PA2KeychainStoreItemResult) updateValue:(nonnull NSData*)data
									forKey:(nonnull NSString*)key;

/** Updates data for given key in the Keychain asynchronously, returns the result in a callback. If a value for given key does not exist, 'PA2KeychainStoreItemResult_NotFound' is returned.
 
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

/** Delete all data that are stored for all keychains.
 */
+ (void) deleteAllData;

/** Delete all data that are stored in this keychain.
 */
- (void) deleteAllData;

/** Retrieve the data for given key in the Keychain synchronously, in case record requires Touch ID, use given prompt in the dialog.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @param prompt Prompt displayed to user when requesting record with Touch ID.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString *)key status:(nullable OSStatus *)status prompt:(nullable NSString*)prompt;

/** Retrieve the data for given key in the Keychain synchronously.
 
 @param key Key for which to retrieve the value.
 @param status Status that was returned when obtaining keychain item.
 @return Data for given key, or 'nil' in case no data are present or when an error occurred.
 */
- (nullable NSData*) dataForKey:(nonnull NSString*)key status:(nullable OSStatus *)status;

/** Retrieve the data for given key in the Keychain asynchronously, return result in a callbacl.
 
 @param key Key for which to retrieve the value.
 @param prompt Prompt displayed to user when requesting record with Touch ID.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
			 prompt:(nullable NSString*)prompt
		 completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion;

/** Retrieve the data for given key in the Keychain asynchronously, return result in a callback.
 
 @param key Key for which to retrieve the value.
 @param completion Callback with the retrieved data.
 */
- (void) dataForKey:(nonnull NSString*)key
		 completion:(nonnull void(^)(NSData * _Nullable data, OSStatus status))completion;

/** Checks if a value exists for given key in Keychain synchronously.
 
 @param key Key for which to check the value presence.
 @return Returns YES in case record for given key was found, NO otherwise.
 */
- (BOOL) containsDataForKey:(nonnull NSString*)key;

/** Checks if a value exists for given key in Keychain asynchronously, return result in a callback.
 
 @param key Key for which to check the value presence.
 @param completion Callback with the information about value presence.
 */
- (void) containsDataForKey:(nonnull NSString*)key
				 completion:(nonnull void(^)(BOOL containsValue))completion;

/** Return all items that are stored in this Keychain.
 
 If some of the items are protected by Touch ID, Touch ID authentication is required.
 
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items, operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItems;

/** Return all items that are stored in this Keychain.

 If some of the items are protected by Touch ID, Touch ID authentication is required and prompt message specified as a parameter is used.

 @param prompt Prompt displayed in case that Touch ID authentication is required.
 @param status Status that was returned when obtaining keychain item.
 @return Dictionary with all keychain items (account name as a key, secret as a value), or null of there are no items, operation is cancelled or any error occurs.
 */
- (nullable NSDictionary*) allItemsWithPrompt:(nullable NSString*)prompt withStatus: (nullable OSStatus *)status;

/** Convenience method that checks if Touch ID can be used on current system.
 
 @return YES if Touch ID can be used (iOS 9.0+), NO otherwise.
 */
+ (BOOL) canUseTouchId;

@end
