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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthToken.h>
#import <PowerAuth2ForExtensions/PowerAuthSessionStatusProvider.h>

#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateRemoteTokenProvider.h"
#import "PA2TokenDataLock.h"

@class PowerAuthKeychain;

/**
 The PA2PrivateTokenKeychainStore object implements token store which
 stores tokens into the IOS keychain. Each created token has its own
 database entry, with using token's name as unique identifier.
 
 The class also implements fetching token from the PA2 server if
 the remote token provider is set in constructor.
 */
@interface PA2PrivateTokenKeychainStore : NSObject<PowerAuthPrivateTokenStore>

/**
 A PowerAuth onfiguration object provided during the object initialization.
 */
@property (nonatomic, strong, readonly) PowerAuthConfiguration * configuration;
/**
 A keychain for storing tokens.
 */
@property (nonatomic, strong, readonly) PowerAuthKeychain * keychain;
/**
 An associated status provider.
 */
@property (nonatomic, weak, readonly) id<PowerAuthSessionStatusProvider> statusProvider;
/**
 An associated remote token provider.
 */
@property (nonatomic, weak, readonly) id<PA2PrivateRemoteTokenProvider> remoteTokenProvider;
/**
 If YES then in-memory cache will be used for access speedup.
 By default is YES for IOS and watchOS and NO for IOS extensions.
 */
@property (nonatomic, assign) BOOL allowInMemoryCache;

/**
 Initializes keychain token store with configuration, status provider, remote provider
 and keychain as persisting storage.
 
 @param configuration PowerAuth configuration object. The store is keeping a strong reference to this object.
 @param keychain PA2Keychain for storage. The store is keeping a strong reference to this object.
 @param statusProvider An object providing session's status. The store keeps a weak reference.
 @param remoteProvider An object for accessing remote token, when token is not cached locally. The store keeps a weak reference.
 @param dataLock An object implementing token store locking.
 @param localLock An optional local lock that implements recursive locking. If not provided, then internal lock is created.
 */
- (id) initWithConfiguration:(PowerAuthConfiguration*)configuration
                    keychain:(PowerAuthKeychain*)keychain
              statusProvider:(id<PowerAuthSessionStatusProvider>)statusProvider
              remoteProvider:(id<PA2PrivateRemoteTokenProvider>)remoteProvider
                    dataLock:(id<PA2TokenDataLock>)dataLock
                   localLock:(id<NSLocking>)localLock;


// Token data identifiers

/**
 Returns string representing a prefix to all keys stored in keychain and valid for given instanceId.
 */
+ (NSString*) keychainPrefixForInstanceId:(NSString*)instanceId;

/**
 Returns fully qualified identifier for token stored in the keychain for given token name and for session with instanceId.
 */
+ (NSString*) identifierForTokenName:(NSString*)name forInstanceId:(NSString*)instanceId;

@end
