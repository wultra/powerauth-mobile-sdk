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
#import "PA2Keychain.h"
#import "PA2Client.h"

/** Class that is used to provide default (shared) Keychain storage configuration.
 */
@interface PA2KeychainConfiguration : NSObject

/** Access group name used by the PowerAuthSDK keychain instances.
 */
@property (nonatomic, strong, nullable) NSString	*keychainAttribute_AccessGroup;

/** Suite name used by the NSUserDefaults that check for Keychain data presence.
 
 If the value is not set, `standardUserDefaults` are used. Otherwise, user defaults with given suite name are created. In case a developer started using SDK with no suite name specified, the developer is responsible for migrating data to the new `NSUserDefaults` before using the SDK with the new suite name.
 */
@property (nonatomic, strong, nullable) NSString	*keychainAttribute_UserDefaultsSuiteName;

/** Name of the Keychain service used to store statuses for different PowerAuth instances.
 */
@property (nonatomic, strong, nonnull) NSString	*keychainInstanceName_Status;

/** Name of the Keychain service used to store possession fator related key (one value for all PowerAuth instances).
 */
@property (nonatomic, strong, nonnull) NSString	*keychainInstanceName_Possession;

/** Name of the Keychain service used to store biometry related keys for different PowerAuth instances.
 */
@property (nonatomic, strong, nonnull) NSString	*keychainInstanceName_Biometry;

/** Name of the Keychain key used to store possession fator related key in an associated service.
 */
@property (nonatomic, strong, nonnull) NSString	*keychainKey_Possession;

/** Return the shared in stance of a Keychain configuration object.
 
 @return Shared instance of a Keychain configuration.
 */
+ (nonnull PA2KeychainConfiguration*) sharedInstance;

@end

/** Class that is used to provide default (shared) RESTful API client configuration.
 */
@interface PA2ClientConfiguration : NSObject

/** Property that specifies the default HTTP client request timeout. The default value is 20.0 (seconds).
 */
@property (nonatomic, assign) NSTimeInterval defaultRequestTimeout;

/** Property that specifies the SSL validation strategy applied by the client. The default value is the default NSURLSession behavior.
 */
@property (nonatomic, strong, nullable) id<PA2ClientSslValidationStrategy> sslValidationStrategy;

/** Return the shared in stance of a client configuration object.
 
 @return Shared instance of a client configuration.
 */
+ (nonnull PA2ClientConfiguration*) sharedInstance;

@end

/** Class that represents a PowerAuthSDK instance configuration.
 */
@interface PowerAuthConfiguration : NSObject

/** Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
 */
@property (nonatomic, strong, nonnull) NSString	*instanceId;

/** Base URL to the PowerAuth 2.0 Standard RESTful API (the URL part before "/pa/...").
 */
@property (nonatomic, strong, nonnull) NSString	*baseEndpointUrl;

/** APPLICATION_KEY as defined in PowerAuth 2.0 specification - a key identifying an application version.
 */
@property (nonatomic, strong, nonnull) NSString	*appKey;

/** APPLICATION_SECRET as defined in PowerAuth 2.0 specification - a secret associated with an application version.
 */
@property (nonatomic, strong, nonnull) NSString	*appSecret;

/** KEY_SERVER_MASTER_PUBLIC as defined in PowerAuth 2.0 specification - a master server public key.
 */
@property (nonatomic, strong, nonnull) NSString	*masterServerPublicKey;

/** This value specifies 'key' used to store this PowerAuthSDK instance biometry related key in the biometry key keychain.
 */
@property (nonatomic, strong, nonnull) NSString *keychainKey_Biometry;

/** Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
 */
@property (nonatomic, strong, nullable) NSData	*externalEncryptionKey;

/** Validate that the configuration is properly set (all required values were filled in).
 */
- (BOOL) validateConfiguration;

@end
