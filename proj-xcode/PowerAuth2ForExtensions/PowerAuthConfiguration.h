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

#import <PowerAuth2ForExtensions/PowerAuthSharingConfiguration.h>

/** Class that represents a PowerAuthSDK instance configuration.
 */
@interface PowerAuthConfiguration : NSObject<NSCopying>

/** Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
 */
@property (nonatomic, strong, nonnull) NSString *instanceId;

/** Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
 */
@property (nonatomic, strong, nonnull) NSString *baseEndpointUrl;

/** APPLICATION_KEY as defined in PowerAuth specification - a key identifying an application version.
 */
@property (nonatomic, strong, nonnull) NSString *appKey;

/** APPLICATION_SECRET as defined in PowerAuth specification - a secret associated with an application version.
 */
@property (nonatomic, strong, nonnull) NSString *appSecret;

/** KEY_SERVER_MASTER_PUBLIC as defined in PowerAuth specification - a master server public key.
 */
@property (nonatomic, strong, nonnull) NSString *masterServerPublicKey;

/** This value specifies 'key' used to store this PowerAuthSDK instance biometry related key in the biometry key keychain.
 */
@property (nonatomic, strong, nonnull) NSString *keychainKey_Biometry;

/** Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
 */
@property (nonatomic, strong, nullable) NSData  *externalEncryptionKey;

/**
 If set to YES, then PowerAuthSDK will not automatically upgrade activation to a newer protocol version.
 This option should be used only for the testing purposes.
 
 Default and recommended value is `NO`.
 */
@property (nonatomic, assign) BOOL disableAutomaticProtocolUpgrade;

/**
 If set, then this instance of PowerAuthSDK can be shared between multiple vendor applications.
 */
@property (nonatomic, strong, nullable) PowerAuthSharingConfiguration * sharingConfiguration;

/** Validate that the configuration is properly set (all required values were filled in).
 */
- (BOOL) validateConfiguration;

@end
