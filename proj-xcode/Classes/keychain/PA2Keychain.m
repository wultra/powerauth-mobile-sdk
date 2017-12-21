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
	return [self addValue:data forKey:key useTouchId:NO];
}

- (PA2KeychainStoreItemResult)addValue:(NSData *)data forKey:(NSString *)key useTouchId:(BOOL)useTouchId {
	if ([self containsDataForKey:key]) {
		return PA2KeychainStoreItemResult_Duplicate;
	} else {
		return [self implAddValue:data forKey:key useTouchId:useTouchId];
	}
}

- (void) addValue:(NSData*)data forKey:(NSString*)key completion:(void(^)(PA2KeychainStoreItemResult status))completion {
	[self addValue:data forKey:key useTouchId:NO completion:completion];
}

- (void) addValue:(NSData*)data forKey:(NSString*)key useTouchId:(BOOL)useTouchId completion:(void(^)(PA2KeychainStoreItemResult status))completion {
	[self containsDataForKey:key completion:^(BOOL containsValue) {
		if (containsValue) {
			completion(PA2KeychainStoreItemResult_Duplicate);
		} else {
			completion([self implAddValue:data forKey:key useTouchId:useTouchId]);
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

#pragma mark - Touch ID support

+ (BOOL) canUseTouchId
{
#if defined(PA2_EXTENSION_SDK)
	// On watchOS or extensions, always return NO
	return NO;
#else
	// Regular IOS
	// Don't allow Touch ID before iOS 9.0
	if (@available(iOS 9, *)) {
		// Check if Touch ID can be used on current system
		NSError *error = nil;
		LAContext *context = [[LAContext alloc] init];
		BOOL hasTouchId = [context canEvaluatePolicy:kLAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
		if (error.code == kLAErrorTouchIDNotAvailable) {
			hasTouchId = NO;
		}
		return hasTouchId;
	}
	return NO;
#endif
}

#pragma mark - Private methods

- (PA2KeychainStoreItemResult) implAddValue:(NSData*)data forKey:(NSString*)key useTouchId:(BOOL)useTouchId {
	
	// Return if iOS version is lower than iOS 9.0 - we cannot securely store a biometric key here.
	// Call is moved here so that we spare further object allocations.
	if (useTouchId) {
		if (![PA2Keychain canUseTouchId]) {
			return PA2KeychainStoreItemResult_TouchIDNotAvailable;
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
		flags = useTouchId ? kSecAccessControlTouchIDAny : kNilOptions;
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
