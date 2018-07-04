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

#import "PA2Keychain.h"
#import "PA2PrivateMacros.h"

#if !defined(PA2_EXTENSION_SDK)
// LA is not available for watchOS or Extensions
#import <LocalAuthentication/LocalAuthentication.h>
#endif

@implementation PA2Keychain {
	NSDictionary *_baseQuery;
}

#pragma mark - Initializer

- (instancetype) initWithIdentifier:(NSString*)identifier {
	return [self initWithIdentifier:identifier accessGroup:nil];
}

- (instancetype) initWithIdentifier:(NSString*)identifier accessGroup:(NSString*)accessGroup {
	self = [super init];
	if (self) {
		_identifier = identifier;
		_accessGroup = accessGroup;
		_baseQuery = [NSMutableDictionary dictionary];
		[_baseQuery setValue:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];
		[_baseQuery setValue:_identifier							forKey:(__bridge id)kSecAttrService];
		[_baseQuery setValue:@YES									forKey:(__bridge id)kSecReturnData];
		if (_accessGroup != nil) {
			[_baseQuery setValue:_accessGroup							forKey:(__bridge id)kSecAttrAccessGroup];
		}
	}
	return self;
}

#pragma mark - Adding a new records

- (PA2KeychainStoreItemResult)addValue:(NSData *)data forKey:(NSString *)key {
	return [self addValue:data forKey:key useBiometry:NO];
}

- (PA2KeychainStoreItemResult)addValue:(NSData *)data forKey:(NSString *)key useBiometry:(BOOL)useBiometry {
	if ([self containsDataForKey:key]) {
		return PA2KeychainStoreItemResult_Duplicate;
	} else {
		return [self implAddValue:data forKey:key useBiometry:useBiometry];
	}
}

- (void) addValue:(NSData*)data forKey:(NSString*)key completion:(void(^)(PA2KeychainStoreItemResult status))completion {
	[self addValue:data forKey:key useBiometry:NO completion:completion];
}

- (void) addValue:(NSData*)data forKey:(NSString*)key useBiometry:(BOOL)useBiometry completion:(void(^)(PA2KeychainStoreItemResult status))completion {
	[self containsDataForKey:key completion:^(BOOL containsValue) {
		if (containsValue) {
			completion(PA2KeychainStoreItemResult_Duplicate);
		} else {
			completion([self implAddValue:data forKey:key useBiometry:useBiometry]);
		}
	}];
}

#pragma mark - Updating existing records

- (PA2KeychainStoreItemResult)updateValue:(NSData *)data forKey:(NSString *)key {
	if ([self containsDataForKey:key]) {
		return [self implUpdateValue:data forKey:key];
	} else {
		return PA2KeychainStoreItemResult_NotFound;
	}
}

- (void)updateValue:(NSData *)data forKey:(NSString *)key completion:(void (^)(PA2KeychainStoreItemResult))completion {
	[self containsDataForKey:key completion:^(BOOL containsValue) {
		if (containsValue) {
			completion([self implUpdateValue:data forKey:key]);
		} else {
			completion(PA2KeychainStoreItemResult_NotFound);
		}
	}];
}

#pragma mark - Removing records

- (BOOL)deleteDataForKey:(NSString *)key {
	NSMutableDictionary *query = [_baseQuery mutableCopy];
	[query setValue:key forKey:(__bridge id)kSecAttrAccount];
	return SecItemDelete((__bridge CFDictionaryRef)(query)) == errSecSuccess;
}

- (void) deleteDataForKey:(NSString*)key completion:(void(^)(BOOL deleted))completion {
	dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		completion([self deleteDataForKey:key]);
	});
}

+ (void) deleteAllData {
    NSArray *secItemClasses = @[(__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecClassInternetPassword,
                                (__bridge id)kSecClassCertificate,
                                (__bridge id)kSecClassKey,
                                (__bridge id)kSecClassIdentity];
    for (id secItemClass in secItemClasses) {
        NSDictionary *spec = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)spec);
    }
}

- (void) deleteAllData {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
	[query setValue:_identifier								forKey:(__bridge id)kSecAttrService];
	[query setValue:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];
	SecItemDelete((__bridge CFDictionaryRef)(query));
}

#pragma mark - Obtaining record information

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status {
	return [self dataForKey:key status:status prompt:nil];
}

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status prompt:(NSString*)prompt {
	
	// Build query
	NSMutableDictionary *query = [_baseQuery mutableCopy];
	[query setValue:key forKey:(__bridge id)kSecAttrAccount];
	
	// Add prompt for Touch ID
	if (prompt) {
		[query setValue:prompt forKey:(__bridge id)kSecUseOperationPrompt];
	}
	
	// Obtain data and return result
	CFTypeRef dataTypeRef = NULL;
	OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
	if (status != NULL) {
		*status = s;
	}
	if (s == errSecSuccess) {
		return (__bridge_transfer NSData *)dataTypeRef;
	}
	else {
		return nil;
	}
}

- (void) dataForKey:(NSString*)key prompt:(NSString*)prompt completion:(void(^)(NSData *data, OSStatus status))completion {
	dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		OSStatus status;
		NSData *value = [self dataForKey:key status:&status prompt:prompt];
		completion(value, status);
	});
}

- (void) dataForKey:(NSString*)key completion:(void(^)(NSData *data, OSStatus status))completion {
	dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		OSStatus status;
		NSData *value = [self dataForKey:key status:&status];
		completion(value, status);
	});
}

static void _AddUseNoAuthenticationUI(NSMutableDictionary * query)
{
	if (@available(iOS 9, watchOS 2, *)) {
		// IOS 9+
		query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
	} else {
		// IOS 8, unfortunately, we have to force warning off for the next line
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		query[(__bridge id)kSecUseNoAuthenticationUI] = @YES;
#pragma clang diagnostic pop
	}
}

- (BOOL) containsDataForKey:(NSString *)key {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
	[query setValue:_identifier								forKey:(__bridge id)kSecAttrService];
	[query setValue:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];
	[query setValue:key										forKey:(__bridge id)kSecAttrAccount];
	_AddUseNoAuthenticationUI(query);
	if (_accessGroup != nil) {
		[query setValue:_accessGroup						forKey:(__bridge id)kSecAttrAccessGroup];
	}
	
	CFTypeRef dataTypeRef = NULL;
	OSStatus const status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
	if (status == errSecItemNotFound
		|| status == errSecUnimplemented
		|| status == errSecParam
		|| status == errSecUserCanceled
		|| status == errSecBadReq
		|| status == errSecNotAvailable
		|| status == errSecDecode) {
		return NO;
	} else {
		return YES;
	}
}

- (void) containsDataForKey:(NSString*)key completion:(void(^)(BOOL containsValue))completion {
	dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		BOOL containsValue = [self containsDataForKey:key];
		completion(containsValue);
	});
}

#pragma mark - Data in-memory caching

- (NSDictionary*) allItems {
    return [self allItemsWithPrompt:nil withStatus:nil];
}

- (NSDictionary*) allItemsWithPrompt:(NSString*)prompt withStatus: (OSStatus *)status {
    // Build query to return all results
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
    [query setObject:@YES forKey:(__bridge id)kSecReturnAttributes];

    // Add prompt for Touch ID
    if (prompt) {
        [query setValue:prompt forKey:(__bridge id)kSecUseOperationPrompt];
    }

    // Obtain data and return result
    CFTypeRef dataTypeRef = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    NSArray *queryResult = (__bridge_transfer NSArray *)dataTypeRef;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    if (status != NULL) {
        *status = s;
    }

    if (s == errSecSuccess) {
        for (NSDictionary *const item in queryResult) {
            NSString *key = [item valueForKey:(__bridge id)kSecAttrAccount];
            NSData *value = [item valueForKey:(__bridge id)kSecValueData];
            [result setObject:value forKey:key];
        }
    }
    else {
        return nil;
    }
    return result;
}

#pragma mark - Biometry support

/**
 Private helper function to convert LABiometryType enum into our PA2BiometricAuthenticationType
 */
API_AVAILABLE(ios(11.0))
static PA2BiometricAuthenticationType _LABiometryTypeToPAType(LABiometryType bt)
{
	if (bt == LABiometryTypeTouchID) {
		return PA2BiometricAuthenticationType_TouchID;
	} else if (bt == LABiometryTypeFaceID) {
		return PA2BiometricAuthenticationType_FaceID;
	}
	// Looks like Apple introduced a new biometry type. We should try to continue,
	// and pretend that TouchID is available. Application's UI will probably display
	// wrong information, but at least it may work.
	PA2Log(@"Warning: LAContext.biometryType contains unknown biometryType %@.", @(bt));
	return PA2BiometricAuthenticationType_TouchID;
}

/**
 A private function returns full information about biometric support on the system. The method internally
 uses `LAContext.canEvaluatePolicy()`.
 */
static PA2BiometricAuthenticationInfo _getBiometryInfo()
{
	PA2BiometricAuthenticationInfo info = { PA2BiometricAuthenticationStatus_NotSupported, PA2BiometricAuthenticationType_None };
#if !defined(PA2_EXTENSION_SDK)
	// Check is available only for regular iOS applications
	if (@available(iOS 9, *)) {
		LAContext * context = [[LAContext alloc] init];
		NSError * error = nil;
		BOOL canEvaluate = [context canEvaluatePolicy:kLAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
		if (canEvaluate) {
			// If we can evaluate, then everything is quite simple.
			info.currentStatus = PA2BiometricAuthenticationStatus_Available;
			// Now check the type of biometry
			if (@available(iOS 11.0, *)) {
				info.biometryType = _LABiometryTypeToPAType(context.biometryType);
			} else {
				// No FaceID before iOS11, so it has to be TouchID
				info.biometryType = PA2BiometricAuthenticationType_TouchID;
			}
			//
		} else {
			// In case of error we cannot evaluate, but the type of biometry can be determined.
			NSInteger code = [error.domain isEqualToString:LAErrorDomain] ? error.code : 0;
			if (@available(iOS 11.0, *)) {
				// On iOS 11 its quite simple, we have type property available and status can be determined
				// from the error.
				LABiometryType bt = context.biometryType;
				// The short living LABiometryNone was introduced in IOS 11.0 and deprecated in 11.2 :D
				// Following condition will probably cause a warning in future SDKs. If this happens, then we
				// can safely use the 0 constant, because the new LABiometryTypeNone requires targeting IOS 11.2+,
				// and that's not acceptable. Both constants are equal to 0...
				if (bt != LABiometryNone) {
					info.biometryType = _LABiometryTypeToPAType(bt);
					if (code == LAErrorBiometryLockout) {
						info.currentStatus = PA2BiometricAuthenticationStatus_Lockout;
					} else if (code == LAErrorBiometryNotEnrolled) {
						info.currentStatus = PA2BiometricAuthenticationStatus_NotEnrolled;
					} else {
						// The biometry is available, but returned error is unknown.
						PA2Log(@"LAContext.canEvaluatePolicy() failed with error: %@", error);
						info.currentStatus = PA2BiometricAuthenticationStatus_NotAvailable;
					}
				}
			} else {
				// On older systems (IOS 8..10), only Touch ID is available.
				if (code == LAErrorTouchIDLockout) {
					info.currentStatus = PA2BiometricAuthenticationStatus_Lockout;
					info.biometryType  = PA2BiometricAuthenticationType_TouchID;
				} else if (code == LAErrorTouchIDNotEnrolled) {
					info.currentStatus = PA2BiometricAuthenticationStatus_NotEnrolled;
					info.biometryType  = PA2BiometricAuthenticationType_TouchID;
				}
			}
		}
	}
#endif // !defined(PA2_EXTENSION_SDK)
	return info;
}

+ (BOOL) canUseBiometricAuthentication
{
	// The behavior of this property is that it returns YES, only if biometry policy can be evaluated.
	return _getBiometryInfo().currentStatus == PA2BiometricAuthenticationStatus_Available;
}

+ (PA2BiometricAuthenticationType) supportedBiometricAuthentication
{
	PA2BiometricAuthenticationInfo info = _getBiometryInfo();
	// The behavior of this property is that if the biometry policy cannot be evaluated, then returns "None".
	if (info.currentStatus == PA2BiometricAuthenticationStatus_Available) {
		return info.biometryType;
	}
	return PA2BiometricAuthenticationType_None;
}

+ (PA2BiometricAuthenticationInfo) biometricAuthenticationInfo
{
	return _getBiometryInfo();
}


#pragma mark - Private methods

- (PA2KeychainStoreItemResult) implAddValue:(NSData*)data forKey:(NSString*)key useBiometry:(BOOL)useBiometry
{
	// Return if iOS version is lower than iOS 9.0 - we cannot securely store a biometric key here.
	// Call is moved here so that we spare further object allocations.
	if (useBiometry) {
		if (![PA2Keychain canUseBiometricAuthentication]) {
			return PA2KeychainStoreItemResult_BiometryNotAvailable;
		}
	}
	
	// Build default query with base data.
	NSMutableDictionary *query = [_baseQuery mutableCopy];
	[query setValue:key		forKey:(__bridge id)kSecAttrAccount];
	[query setValue:data	forKey:(__bridge id)kSecValueData];
	_AddUseNoAuthenticationUI(query);
	
	// If the system version is iOS 9.0+, use Touch ID if requested (kSecAccessControlTouchIDAny), or use kNilOptions
	SecAccessControlCreateFlags flags;
	if (@available(iOS 9, *)) {
		flags = useBiometry ? kSecAccessControlTouchIDAny : kNilOptions;
	} else {
		flags = kNilOptions;
	}

	// Create access control object
	CFErrorRef error = NULL;
	SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &error);
	
	// Check for access errors
	if (sacObject == NULL || error != NULL) {
		if (sacObject != NULL) { // make sure to release the object
			CFRelease(sacObject);
		}
		return PA2KeychainStoreItemResult_Other;
	}
	
	// Add the access control constraint
	[query setValue:(__bridge_transfer id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
	
	// Return result of kechain item add.
	OSStatus keychainResult = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
	switch (keychainResult) {
		case errSecDuplicateItem:
			return PA2KeychainStoreItemResult_Duplicate;
		case errSecSuccess:
			return PA2KeychainStoreItemResult_Ok;
		default:
			return PA2KeychainStoreItemResult_Other;
	}
}

- (PA2KeychainStoreItemResult) implUpdateValue:(NSData*)data forKey:(NSString*)key {
	
	// Create access control object
	CFErrorRef error = NULL;
	SecAccessControlCreateFlags flags = kNilOptions;
	SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &error);
	
	// Build default query with base data.
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
	[query setValue:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];
	[query setValue:_identifier								forKey:(__bridge id)kSecAttrService];
	[query setValue:key										forKey:(__bridge id)kSecAttrAccount];
	if (_accessGroup != nil) {
		[query setValue:_accessGroup						forKey:(__bridge id)kSecAttrAccessGroup];
	}
	
	// Data to be updated.
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	[dictionary setValue:_identifier						forKey:(__bridge id)kSecAttrService];
	[dictionary setValue:key								forKey:(__bridge id)kSecAttrAccount];
	[dictionary setValue:data								forKey:(__bridge id)kSecValueData];
	[dictionary setValue:(__bridge_transfer id)sacObject	forKey:(__bridge id)kSecAttrAccessControl];
	
	// Return result of keychain item update.
	OSStatus keychainResult =  SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)dictionary);
	switch (keychainResult) {
		case errSecItemNotFound:
			return PA2KeychainStoreItemResult_NotFound;
		case errSecSuccess:
			return PA2KeychainStoreItemResult_Ok;
		default:
			return PA2KeychainStoreItemResult_Other;
	}
}

@end
