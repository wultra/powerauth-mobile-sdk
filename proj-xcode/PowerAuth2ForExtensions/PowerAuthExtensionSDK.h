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

#import <PowerAuth2ForExtensions/PowerAuthConfiguration.h>
#import <PowerAuth2ForExtensions/PowerAuthToken.h>
#import <PowerAuth2ForExtensions/PowerAuthSessionStatusProvider.h>
#import <PowerAuth2ForExtensions/PowerAuthKeychainConfiguration.h>
#import <PowerAuth2ForExtensions/PowerAuthAuthorizationHttpHeader.h>

@interface PowerAuthExtensionSDK : NSObject<PowerAuthSessionStatusProvider>

/**
 Instance of the token store object, which provides interface for generating token based authentication headers.
 The current implementation is keeping acquired tokens in the PA2Keychain under the `PA2KeychainConfiguration.keychainInstanceName_TokenStore` service name.
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthTokenStore> tokenStore;

/**
 Instance of configuration, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthConfiguration * configuration;

/**
 A designated initializer.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration*)configuration
                          keychainConfiguration:(nonnull PowerAuthKeychainConfiguration*)keychainConfiguration;

@end
