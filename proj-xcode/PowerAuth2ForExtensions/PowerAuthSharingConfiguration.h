/*
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 The `PowerAuthSharingConfiguration` class contains configuration required for
 PowerAuthSDK instances shared accross multiple applications. The class is not
 used in `PowerAuth2ForWatch` and `PowerAuth2ForExtensions` libraries.
 */
@interface PowerAuthSharingConfiguration : NSObject<NSCopying>

/**
 Use appropriate init method with parameters.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Initialize object with required parameters.
 @param appGroup Name of app group that allows you sharing data between multiple applications. Be aware that the value overrides `PowerAuthKeychainConfiguration.keychainAttribute_UserDefaultsSuiteName` property.
 @param appIdentifier Unique application identifier. This identifier helps you to determine which application
                      currently holds the lock on activation data in a special operations.
 @param keychainAccessGroup Keychain sharing access grorup. Be aware that the value overrides `PowerAuthKeychainConfiguration.keychainAttribute_AccessGroup` property.
 */
- (nonnull instancetype) initWithAppGroup:(nonnull NSString*)appGroup
                            appIdentifier:(nonnull NSString*)appIdentifier
                      keychainAccessGroup:(nonnull NSString*)keychainAccessGroup;

/**
 Name of app group that allows you sharing data between multiple applications.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * appGroup;
/**
 Unique application identifier. This identifier helps you to determine which application
 currently holds the lock on activation data in a special operations.
 
 The length of identifier cannot exceed 127 bytes if represented as UTF8 string. It's recommended
 to use application's main bundle identifier, but in general, it's up to you how you identify your
 own applications.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * appIdentifier;
/**
 Keychain access group name used by the PowerAuthSDK keychain instances.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * keychainAccessGroup;
/**
 Optional identifier of memory shared between the applications in app group. If identifier is not provided
 then PowerAuthSDK calculate unique identifier based on `PowerAuthConfiguration.instanceId`.
 
 You can set this property in case that PowerAuth SDK generates identifier that collide with your application's
 functionality. The configuration of PowerAuthSDK instance always contains an actual identifier used for its
 shared memory initialization, so you can test whether the generated identifier is OK.
 
 The length of identifier cannot exceed 4 bytes if represented as UTF8 string. This is an operating system
 limitation.
 */
@property (nonatomic, strong, nullable) NSString * sharedMemoryIdentifier;

/**
 Validate that the configuration is properly set (all required values were filled in).
 */
- (BOOL) validateConfiguration;

@end
