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

#import <PowerAuth2ForExtensions/PowerAuthKeychain.h>
#import <PowerAuth2ForExtensions/PowerAuthLog.h>

#import "PA2PrivateMacros.h"

#if !defined(PA2_EXTENSION_SDK) && defined(PA2_BIOMETRY_SUPPORT)
// LA is not available for watchOS or Extensions
#import <LocalAuthentication/LocalAuthentication.h>
#include <pthread.h>
#endif

@implementation PowerAuthKeychain {
    NSDictionary *_baseQuery;
}

#pragma mark - Initializer

- (instancetype) initWithIdentifier:(NSString*)identifier
{
    return [self initWithIdentifier:identifier accessGroup:nil];
}

- (instancetype) initWithIdentifier:(NSString*)identifier accessGroup:(NSString*)accessGroup
{
    self = [super init];
    if (self) {
        _identifier = identifier;
        _accessGroup = accessGroup;
        _baseQuery = [NSMutableDictionary dictionary];
        [_baseQuery setValue:(__bridge id)kSecClassGenericPassword  forKey:(__bridge id)kSecClass];
        [_baseQuery setValue:_identifier                            forKey:(__bridge id)kSecAttrService];
        [_baseQuery setValue:@YES                                   forKey:(__bridge id)kSecReturnData];
#if !TARGET_OS_SIMULATOR
        if (_accessGroup != nil) {
            [_baseQuery setValue:_accessGroup                       forKey:(__bridge id)kSecAttrAccessGroup];
        }
#endif
    }
    return self;
}

#pragma mark - Adding a new records

- (PowerAuthKeychainStoreItemResult) addValue:(NSData *)data forKey:(NSString *)key
{
    return [self addValue:data forKey:key access:PowerAuthKeychainItemAccess_None];
}

- (PowerAuthKeychainStoreItemResult) addValue:(nonnull NSData*)data forKey:(nonnull NSString*)key access:(PowerAuthKeychainItemAccess)access
{
    if ([self containsDataForKey:key]) {
        return PowerAuthKeychainStoreItemResult_Duplicate;
    }
    return [self implAddValue:data forKey:key access:access];
}


#pragma mark - Updating existing records

- (PowerAuthKeychainStoreItemResult)updateValue:(NSData *)data forKey:(NSString *)key
{
    if ([self containsDataForKey:key]) {
        return [self implUpdateValue:data forKey:key];
    } else {
        return PowerAuthKeychainStoreItemResult_NotFound;
    }
}

#pragma mark - Removing records

- (BOOL)deleteDataForKey:(NSString *)key
{
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key forKey:(__bridge id)kSecAttrAccount];
    return SecItemDelete((__bridge CFDictionaryRef)(query)) == errSecSuccess;
}

+ (void) deleteAllData
{
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

- (void) deleteAllData
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    SecItemDelete((__bridge CFDictionaryRef)(query));
}

#pragma mark - Obtaining record information

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status
{
    return [self dataForKey:key status:status authentication:nil];
}

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status authentication:(PowerAuthKeychainAuthentication *)authentication
{
    // Build query
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key forKey:(__bridge id)kSecAttrAccount];
    
    // Add authentication for items protected with biometry.
    if (authentication) {
        if (!_AddKeychainAuthentication(query, authentication, status)) {
            return nil;
        }
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


static BOOL _AddKeychainAuthentication(NSMutableDictionary * query, PowerAuthKeychainAuthentication * auth, OSStatus * status)
{
#if PA2_HAS_LACONTEXT == 1
    LAContext * context = auth.context;
    if (context) {
        if (context.interactionNotAllowed) {
            PowerAuthLog(@"LAContext.interactionNotAllowed should not be set to true");
            if (status) { *status = errSecInvalidContext; }
            return NO;
        }
        query[(__bridge id)kSecUseAuthenticationContext] = context;
        return YES;
    }
    NSString * prompt = auth.prompt;
    if (prompt) {
        // kSecUseOperationPrompt is deprecated, so on iOS11+ use LAContext.
        LAContext * context = [[LAContext alloc] init];
        context.localizedReason = prompt;
        query[(__bridge id)kSecUseAuthenticationContext] = context;
        return YES;
    }
    // Missing prompt and context, report errSecInvalidContext as the most reasonable error code.
    PowerAuthLog(@"PowerAuthKeychainAuthentication has no prompt or LAContext set.");
    if (status) { *status = errSecInvalidContext; }
    return NO;
#else
    // PowerAuthKeychainAuthentication is not supported on this platform.
    PowerAuthLog(@"PowerAuthKeychainAuthentication is not supported.");
    if (status) { *status = errSecUnimplemented; }
    return NO;
#endif // PA2_HAS_LACONTEXT
}

static void _AddUseNoAuthenticationUI(NSMutableDictionary * query)
{
    query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
}

- (BOOL) containsDataForKey:(NSString *)key
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    [query setValue:key                                     forKey:(__bridge id)kSecAttrAccount];
    _AddUseNoAuthenticationUI(query);
#if !TARGET_OS_SIMULATOR
    if (_accessGroup != nil) {
        [query setValue:_accessGroup                        forKey:(__bridge id)kSecAttrAccessGroup];
    }
#endif
    
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


#pragma mark - Data in-memory caching

- (NSDictionary*) allItemsWithAuthentication:(PowerAuthKeychainAuthentication *)authentication withStatus:(OSStatus *)status
{
    // Build query to return all results
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
    [query setObject:@YES forKey:(__bridge id)kSecReturnAttributes];

    // Add authentication for items protected with biometry.
    if (authentication) {
        if (!_AddKeychainAuthentication(query, authentication, status)) {
            return nil;
        }
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

- (NSDictionary*) allItems
{
    return [self allItemsWithAuthentication:nil withStatus:nil];
}

#pragma mark - Biometry support

#if !defined(PA2_EXTENSION_SDK) && defined(PA2_BIOMETRY_SUPPORT)
//
// IOS
//

/**
 Private helper function to convert LABiometryType enum into our PowerAuthBiometricAuthenticationType
 */
static PowerAuthBiometricAuthenticationType _LABiometryTypeToPAType(LABiometryType bt)
{
    if (bt == LABiometryTypeTouchID) {
        return PowerAuthBiometricAuthenticationType_TouchID;
    } else if (bt == LABiometryTypeFaceID) {
        return PowerAuthBiometricAuthenticationType_FaceID;
    }
    // Looks like Apple introduced a new biometry type. We should try to continue,
    // and pretend that TouchID is available. Application's UI will probably display
    // wrong information, but at least it may work.
    PowerAuthLog(@"Warning: LAContext.biometryType contains unknown biometryType %@.", @(bt));
    return PowerAuthBiometricAuthenticationType_TouchID;
}

// Distinguish between old, deprecated "TouchID" enums and new with "biometry" in name.
//
// This is required due to a different min-SDK requirements between iOS and Catalyst
// builds. On "iOS", we target iOS 8+, so deprecated constants are still valid.
// On opposite to that, the Catalyst build targets simulated iOS 13+, so the deprecated
// constants causes a few warnings.
//
// The most important thing is that it's just a matter of constants that have the same
// values for both, new and old definitions. Once we target iOS 11.2+, we can freely
// remove this tweak.

// 11.2+
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_11_2
    #define __LABiometryTypeNone                    LABiometryTypeNone
#else
    #define __LABiometryTypeNone                    LABiometryNone
#endif
// 11.3+
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_11_3
    #define __kSecAccessControlBiometryAny          kSecAccessControlBiometryAny
    #define __kSecAccessControlBiometryCurrentSet   kSecAccessControlBiometryCurrentSet
#else
    #define __kSecAccessControlBiometryAny          kSecAccessControlTouchIDAny
    #define __kSecAccessControlBiometryCurrentSet   kSecAccessControlTouchIDCurrentSet
#endif

/**
 Private function returns full information about biometric support on the system. The method internally
 uses `LAContext.canEvaluatePolicy()`.
 */
static PowerAuthBiometricAuthenticationInfo _getBiometryInfo()
{
    PowerAuthBiometricAuthenticationInfo info = { PowerAuthBiometricAuthenticationStatus_NotSupported, PowerAuthBiometricAuthenticationType_None };
    LAContext * context = [[LAContext alloc] init];
    NSError * error = nil;
    BOOL canEvaluate = [context canEvaluatePolicy:kLAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    if (canEvaluate) {
        // If we can evaluate, then everything is quite simple.
        info.currentStatus = PowerAuthBiometricAuthenticationStatus_Available;
        info.biometryType = _LABiometryTypeToPAType(context.biometryType);
        //
    } else {
        // In case of error we cannot evaluate, but the type of biometry can be determined.
        NSInteger code = [error.domain isEqualToString:LAErrorDomain] ? error.code : 0;
        LABiometryType bt = context.biometryType;
        if (bt != __LABiometryTypeNone) {
            info.biometryType = _LABiometryTypeToPAType(bt);
            if (code == LAErrorBiometryLockout) {
                info.currentStatus = PowerAuthBiometricAuthenticationStatus_Lockout;
            } else if (code == LAErrorBiometryNotEnrolled) {
                info.currentStatus = PowerAuthBiometricAuthenticationStatus_NotEnrolled;
            } else {
                // The biometry is available, but returned error is unknown.
                PowerAuthLog(@"LAContext.canEvaluatePolicy() failed with error: %@", error);
                info.currentStatus = PowerAuthBiometricAuthenticationStatus_NotAvailable;
            }
        }
    }
    return info;
}

/**
 Translates PowerAuthKeychainItemAccess into SecAccessControlCreateFlags depending on access mode.
 */
static SecAccessControlCreateFlags _getBiometryAccessControlFlags(PowerAuthKeychainItemAccess access)
{
    if (access != PowerAuthKeychainItemAccess_None) {
        switch (access) {
            case PowerAuthKeychainItemAccess_AnyBiometricSet:
                return __kSecAccessControlBiometryAny;
            case PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode:
                return __kSecAccessControlBiometryAny | kSecAccessControlOr | kSecAccessControlDevicePasscode;
            case PowerAuthKeychainItemAccess_CurrentBiometricSet:
                return __kSecAccessControlBiometryCurrentSet;
            default:
                break;
        }
    }
    // If biometry is not supporte or not requested, use the kNilOptions.
    return kNilOptions;
}

+ (BOOL) tryLockBiometryAndExecuteBlock:(void (^_Nonnull)(void))block
{
    // Initialize mutex
    static pthread_mutex_t biometricMutex;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        pthread_mutex_init(&biometricMutex, NULL);
    });
    
    // Try to acquire biometric lock.
    if (pthread_mutex_trylock(&biometricMutex) != 0) {
        PowerAuthLog(@"WARNING: Cannot execute more than one biometric authentication request at the same time. This request is going to be canceled.");
        return NO;
    }
    // Execute block
    block();
    // Unlock mutex and return success.
    pthread_mutex_unlock(&biometricMutex);
    return YES;
}

#else  // !defined(PA2_EXTENSION_SDK)
//
// watchOS + IOS App Extensions
//

/**
 Returns information about biometric support on the system. This is a special implementation
 returning information that biometry is not supported on watchOS & IOS App Extension.
 */
static PowerAuthBiometricAuthenticationInfo _getBiometryInfo()
{
    PowerAuthBiometricAuthenticationInfo info = { PowerAuthBiometricAuthenticationStatus_NotSupported, PowerAuthBiometricAuthenticationType_None };
    return info;
}

/**
 This platform doesn't support biometry, so always return kNilOptions.
 */
static SecAccessControlCreateFlags _getBiometryAccessControlFlags(PowerAuthKeychainItemAccess access)
{
    return kNilOptions;
}

/**
 Do nothing on watchOS or when the class is running in app extension.
 */
+ (BOOL) tryLockBiometryAndExecuteBlock:(void (^_Nonnull)(void))block
{
    return NO;
}

#endif // !defined(PA2_EXTENSION_SDK) && defined(PA2_BIOMETRY_SUPPORT)

//
// High level biometry interfaces
//

+ (BOOL) canUseBiometricAuthentication
{
    // The behavior of this property is that it returns YES, only if biometry policy can be evaluated.
    return _getBiometryInfo().currentStatus == PowerAuthBiometricAuthenticationStatus_Available;
}

+ (PowerAuthBiometricAuthenticationType) supportedBiometricAuthentication
{
    PowerAuthBiometricAuthenticationInfo info = _getBiometryInfo();
    // The behavior of this property is that if the biometry policy cannot be evaluated, then returns "None".
    if (info.currentStatus == PowerAuthBiometricAuthenticationStatus_Available) {
        return info.biometryType;
    }
    return PowerAuthBiometricAuthenticationType_None;
}

+ (PowerAuthBiometricAuthenticationInfo) biometricAuthenticationInfo
{
    return _getBiometryInfo();
}

#pragma mark - Private methods

static BOOL _AddAccessControlObject(NSMutableDictionary * dictionary, BOOL isAddOperation, PowerAuthKeychainItemAccess access)
{
#if TARGET_OS_SIMULATOR
    //
    // Workaround for bug in iOS13 simulator (Xcode 11)
    //
    // iOS13 simulator are not able to store the data to keychain when AC object is present in the query.
    // In this case, we simply skip this step.
    //
    // Associated ticket: https://github.com/wultra/powerauth-mobile-sdk/issues/248
    //
    if (@available(iOS 13, *)) {
        return YES;
    }
#endif
    SecAccessControlCreateFlags flags;
    if (isAddOperation) {
        // For add operation, translate requested access to control flags.
        flags = _getBiometryAccessControlFlags(access);
    } else {
        // For update operation, or if biometry is not requested, use the kNilOptions.
        flags = kNilOptions;
    }
    // Create access control object
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &error);
    if (sacObject == NULL || error != NULL) {
        // make sure to release the object
        if (sacObject != NULL) {
            CFRelease(sacObject);
        }
        return NO;
    }
    // Add the access control constraint to the query.
    [dictionary setValue:(__bridge_transfer id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
    return YES;
}

- (PowerAuthKeychainStoreItemResult) implAddValue:(NSData*)data forKey:(NSString*)key access:(PowerAuthKeychainItemAccess)access
{
    // Return if iOS version is lower than iOS 9.0 - we cannot securely store a biometric key here.
    // Call is moved here so that we spare further object allocations.
    if (access != PowerAuthKeychainItemAccess_None) {
        if (![PowerAuthKeychain canUseBiometricAuthentication]) {
            return PowerAuthKeychainStoreItemResult_BiometryNotAvailable;
        }
    }
    
    // Build default query with base data.
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key     forKey:(__bridge id)kSecAttrAccount];
    [query setValue:data    forKey:(__bridge id)kSecValueData];
    _AddUseNoAuthenticationUI(query);
    if (!_AddAccessControlObject(query, YES, access)) {
        return PowerAuthKeychainStoreItemResult_Other;
    }
    
    // Return result of kechain item add.
    OSStatus keychainResult = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    switch (keychainResult) {
        case errSecDuplicateItem:
            return PowerAuthKeychainStoreItemResult_Duplicate;
        case errSecSuccess:
            return PowerAuthKeychainStoreItemResult_Ok;
        default:
            return PowerAuthKeychainStoreItemResult_Other;
    }
}

- (PowerAuthKeychainStoreItemResult) implUpdateValue:(NSData*)data forKey:(NSString*)key
{
    // Build default query with base data.
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:key                                     forKey:(__bridge id)kSecAttrAccount];
#if !TARGET_OS_SIMULATOR
    if (_accessGroup != nil) {
        [query setValue:_accessGroup                        forKey:(__bridge id)kSecAttrAccessGroup];
    }
#endif
    
    // Data to be updated.
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    [dictionary setValue:_identifier                        forKey:(__bridge id)kSecAttrService];
    [dictionary setValue:key                                forKey:(__bridge id)kSecAttrAccount];
    [dictionary setValue:data                               forKey:(__bridge id)kSecValueData];
    if (!_AddAccessControlObject(dictionary, NO, PowerAuthKeychainItemAccess_None)) {
        return PowerAuthKeychainStoreItemResult_Other;
    }
    
    // Return result of keychain item update.
    OSStatus keychainResult =  SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)dictionary);
    switch (keychainResult) {
        case errSecItemNotFound:
            return PowerAuthKeychainStoreItemResult_NotFound;
        case errSecSuccess:
            return PowerAuthKeychainStoreItemResult_Ok;
        default:
            return PowerAuthKeychainStoreItemResult_Other;
    }
}

@end

// MARK: - Deprecated implementation

@implementation PowerAuthKeychain (Deprecated)

- (void) addValue:(NSData*)data forKey:(NSString*)key completion:(void(^)(PowerAuthKeychainStoreItemResult status))completion
{
    [self addValue:data forKey:key access:PowerAuthKeychainItemAccess_None completion:completion];
}

- (void) addValue:(NSData*)data forKey:(NSString*)key access:(PowerAuthKeychainItemAccess)access completion:(void(^)(PowerAuthKeychainStoreItemResult status))completion
{
    [self containsDataForKey:key completion:^(BOOL containsValue) {
        if (containsValue) {
            completion(PowerAuthKeychainStoreItemResult_Duplicate);
        } else {
            completion([self implAddValue:data forKey:key access:access]);
        }
    }];
}

- (void)updateValue:(NSData *)data forKey:(NSString *)key completion:(void (^)(PowerAuthKeychainStoreItemResult))completion
{
    [self containsDataForKey:key completion:^(BOOL containsValue) {
        if (containsValue) {
            completion([self implUpdateValue:data forKey:key]);
        } else {
            completion(PowerAuthKeychainStoreItemResult_NotFound);
        }
    }];
}

- (void) deleteDataForKey:(NSString*)key completion:(void(^)(BOOL deleted))completion
{
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        completion([self deleteDataForKey:key]);
    });
}

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status prompt:(NSString*)prompt
{
    PowerAuthKeychainAuthentication * auth = [[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt];
    return [self dataForKey:key status:status authentication:auth];
}

- (void) dataForKey:(NSString*)key prompt:(NSString*)prompt completion:(void(^)(NSData *data, OSStatus status))completion
{
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status;
        NSData *value = [self dataForKey:key status:&status prompt:prompt];
        completion(value, status);
    });
}

- (void) dataForKey:(NSString*)key completion:(void(^)(NSData *data, OSStatus status))completion
{
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status;
        NSData *value = [self dataForKey:key status:&status];
        completion(value, status);
    });
}

- (void) containsDataForKey:(NSString*)key completion:(void(^)(BOOL containsValue))completion
{
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        BOOL containsValue = [self containsDataForKey:key];
        completion(containsValue);
    });
}

- (NSDictionary*) allItemsWithPrompt:(NSString*)prompt withStatus: (OSStatus *)status
{
    PowerAuthKeychainAuthentication * auth = [[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt];
    return [self allItemsWithAuthentication:auth withStatus:status];
}

@end
