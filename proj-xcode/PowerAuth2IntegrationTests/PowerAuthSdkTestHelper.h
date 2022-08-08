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

#import <XCTest/XCTest.h>
#import "PowerAuthTestServerAPI.h"
#import "PowerAuthTestServerConfig.h"
#import "AsyncHelper.h"

@import PowerAuth2;
@import PowerAuthCore;

/**
 Object containing activation data.
 */
@interface PowerAuthSdkActivation: NSObject

@property (nonatomic, strong, readonly) PATSInitActivationResponse * activationData;
@property (nonatomic, strong, readonly) PowerAuthAuthentication * credentials;
@property (nonatomic, strong, readonly) PowerAuthActivationResult * activationResult;
@property (nonatomic, strong, readonly) NSString * activationId;

@property (nonatomic, readonly) BOOL success;
@property (nonatomic, readonly) BOOL alreadyRemoved;

@end

@interface PowerAuthSdkTestHelper : NSObject

/**
 Create default helper.
 */
+ (PowerAuthSdkTestHelper*) createDefault;
/**
 Create custom helper that allows you alter configurations provided to PowerAuthSDK before the instance is created.
 */
+ (PowerAuthSdkTestHelper*) createCustom:(void (^)(PowerAuthConfiguration * configuration, PowerAuthKeychainConfiguration * keychainConfiguration, PowerAuthClientConfiguration * clientConfiguration))configurator;
/**
 Create default configuration.
 */
+ (PowerAuthSdkTestHelper*) clone:(PowerAuthSdkTestHelper*)testHelper
                         withConfiguration:(PowerAuthConfiguration*)configuration;

@property (nonatomic, readonly, strong) PowerAuthSDK * sdk;
@property (nonatomic, readonly, strong) PowerAuthTestServerAPI * testServerApi;
@property (nonatomic, readonly, strong) PowerAuthTestServerConfig * testServerConfig;
@property (nonatomic, strong, readonly) NSString * paVer;

/**
 Print cofiguration to log.
 */
- (void) printConfig;

/**
 Cleanup after tests.
 */
- (void) cleanup;

/**
 Re-instantiate PowerAuthSDK instance with new configuration. If some provided configuration is nil, then the
 appropriate configuration from current PowerAuthSDK will be used.
 */
- (PowerAuthSDK*) reCreateSdkInstanceWithConfiguration:(PowerAuthConfiguration*)configuration
                                 keychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration
                                   clientConfiguration:(PowerAuthClientConfiguration*)clientConfiguration;

// Activation

/**
 Contains information about last successful activation.
 */
@property (nonatomic, strong, readonly) PowerAuthSdkActivation * currentActivation;

/**
 Contains possession only authentication object, after last successful activation.
 */
@property (nonatomic, strong, readonly) PowerAuthAuthentication * authPossession;
/**
 Contains possession + knowledge authentication object, after last successful activation.
 */
@property (nonatomic, strong, readonly) PowerAuthAuthentication * authPossessionWithKnowledge;
/**
 Contains possession + knowledge authentication object. The password is always wrong.
 */
@property (nonatomic, strong, readonly) PowerAuthAuthentication * badAuthPossessionWithKnowledge;

/**
 Returns object with activation data, authentication object, and result of activation.
 You can configure whether the activation can use optional signature during the activation
 and whether the activation should be removed automatically after the creation.
 */
- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
                               activationOtp:(NSString*)activationOtp
                                 removeAfter:(BOOL)removeAfter;

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
                                 removeAfter:(BOOL)removeAfter;

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature;

- (PowerAuthSdkActivation*) createActivation:(BOOL)useSignature
                               activationOtp:(NSString*)activationOtp;

/**
 Prepare activation on server.
 */
- (PATSInitActivationResponse*) prepareActivation:(BOOL)useSignature
                                    activationOtp:(NSString*)activationOtp;

/**
 Creates custom `PowerAuthSdkActivation` from provided data and assign this object to the helper.
 */
- (PowerAuthSdkActivation*) assignCustomActivationData:(PATSInitActivationResponse*)activationData
                                      activationResult:(PowerAuthActivationResult*)activationResult
                                           credentials:(PowerAuthAuthentication*)credentials;

/**
 Returns an activation status object. May return nil if status is not available yet, which is also valid operation.
 */
- (PowerAuthActivationStatus*) fetchActivationStatus;

// Signatures

/**
 Returns @[ signature, nonceB64 ] if succeeded or nil in case of error.
 Doesn't throw test exception on errors.
 */
- (NSArray*) calculateOfflineSignature:(NSData*)data
                                 uriId:(NSString*)uriId
                                  auth:(PowerAuthAuthentication*)auth;

/**
 Returns @[ signature, nonceB64 ] if succeeded or nil in case of error.
 Throws test exception only when header contains invalid data (e.g. parser fail process the header)
 */
- (NSArray*) calculateOnlineSignature:(NSData*)data
                               method:(NSString*)method
                                uriId:(NSString*)uriId
                                 auth:(PowerAuthAuthentication*)auth;

/*
 Returns dictionary created from "X-PowerAuth-Authorization" header's value.
 */
- (NSDictionary*) parseSignatureHeaderValue:(NSString*)headerValue;

/**
 Makes full test against server with signature verification. You can set cripple parameter to following bitmask:
    0x0001 - will cripple auth object (e.g. change factor)
    0x0010 - will cripple data
    0x0100 - will cripple method string
    0x1000 - will cripple uriId string
 */
- (BOOL) validateSignature:(PowerAuthAuthentication*)auth data:(NSData*)data method:(NSString*)method uriId:(NSString*)uriId
                    online:(BOOL)online
                   cripple:(NSInteger)cripple;

// Utils

/**
 Validates password on server. Returns YES if password is valid.
 */
- (BOOL) checkForPassword:(NSString*)password;


/**
 Converts factors from auth object to string.
 */
- (NSString*) authToString:(PowerAuthAuthentication*)auth;


// Core

/**
 Get serialized state from underlying session.
 */
- (NSData*) sessionCoreSerializedState;

/**
 Try to load state into underlying session.
 */
- (BOOL) sessionCoreDeserializeState:(NSData*)state;


/**
 Creates a new PowerAuthAuthentication object with default configuration.
 */
- (PowerAuthAuthentication*) createAuthentication;

// Tokens

/**
 Parse calculated token header into dictionary.
 */
- (NSDictionary*) parseTokenHeaderValue:(NSString*)headerValue;

/**
 Validate token header on test server.
 */
- (BOOL) validateTokenHeader:(PowerAuthAuthorizationHttpHeader*)header
                activationId:(NSString*)activationId
              expectedResult:(BOOL)expectedResult;

@end

@interface PowerAuthAuthentication (TestHelper)
/**
 Create copy from this authentication object, suited for the signature calculation.
 */
- (PowerAuthAuthentication*) copyForSigning;

/**
 Create a broken copy from this authentication object.
 */
- (PowerAuthAuthentication*) copyCrippledForSigning;

@end
