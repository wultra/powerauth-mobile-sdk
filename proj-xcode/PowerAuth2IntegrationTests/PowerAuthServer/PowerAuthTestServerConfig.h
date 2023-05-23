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

#import <Foundation/Foundation.h>

/**
 The `PowerAuthTestServerVersion` defines version of PowerAuth SOAP API.
 If you add some version here then please update `RestEndpoints.bundle/mappings.json`
 */
typedef NS_ENUM(int, PowerAuthTestServerVersion) {
    PATS_V1_0   = 10000,    // V3.1 crypto + Activation OTP
    PATS_V1_1   = 10100,    // V3.1 crypto + Activation OTP
    PATS_V1_2   = 10200,    // V3.1 crypto + Activation OTP
    PATS_V1_2_5 = 10205,    // V3.1 crypto + Activation OTP
    PATS_V1_3   = 10300,    // V3.1 crypto + Activation OTP, applicationId as String
    PATS_V1_4   = 10400,    // V3.1 crypto + Activation OTP, applicationId as String
    PATS_V1_5   = 10500,    // V3.1 crypto + Activation OTP, applicationId as String, userInfo
};

/**
 The `PowerAuthProtocolVersion` defines version of PowerAuth Protocol.
 */
typedef NS_ENUM(int, PowerAuthProtocolVersion) {
    PATS_P2,        // V2 crypto
    PATS_P3,        // V3 crypto
    PATS_P31,       // V3.1 crypto
};

/**
 Function converts server version into general protocol version.
 */
extern PowerAuthProtocolVersion PATSProtoVer(PowerAuthTestServerVersion serverVer);

/**
 The `PowerAuthTestServerConfig` object contains a configuration required for inregration
 testing. You can create a default config, or load it from JSON file.
 */
@interface PowerAuthTestServerConfig : NSObject

/**
 String with URL to REST API
 */
@property (nonatomic, strong, readonly) NSString * enrollmentUrl;
/**
 String with URL to SOAP API
 */
@property (nonatomic, strong, readonly) NSString * serverApiUrl;
/**
 If set, then WS-Security header will be added to SOAP requests.
 */
@property (nonatomic, strong, readonly) NSString * serverApiUsername;
/**
 If set, then WS-Security header will be added to SOAP requests.
 */
@property (nonatomic, strong, readonly) NSString * serverApiPassword;
/**
 String with version of SOAP API. "V2" & "V3" is expected in JSON config.
 "V2" is the default value. Loaded after the connection to server is established.
 */
@property (nonatomic, assign) PowerAuthTestServerVersion serverApiVersion;
/**
 A name for application, which will be used on the PA2 server.
 Default value is @"AutomaticTest-IOS"
 */
@property (nonatomic, strong, readonly) NSString * powerAuthAppName;
/**
 An application's version name used on the PA2 server. 
 Default value is @"default"
 */
@property (nonatomic, strong, readonly) NSString * powerAuthAppVersion;
/**
 An user for whom the activations will be created.
 Default value is @"TestUserIOS"
 */
@property (nonatomic, strong, readonly) NSString * userIdentifier;
/**
 A name for newly created activations.
 Default value is @"Testing on " + short device description
 */
@property (nonatomic, strong, readonly) NSString * userActivationName;
/**
 If YES, then activation is automatically commited on the server.
 */
@property (nonatomic, readonly) BOOL isServerAutoCommit;
/**
 A content of original dictionary used to create this configuration.
 */
@property (nonatomic, strong, readonly) NSDictionary * configDictionary;

/**
 Returns value from `configDictionary` with given key, or `defaultValue` if no such value is available.
 */
- (id) configValueForKey:(NSString*)key defaultValue:(id)defaultValue;

/**
 Creates a default configuration for a server, placed at "http://localhost" base domain.
 */
+ (instancetype) defaultConfig;

/**
 Creates a configuration from given JSON file.
 */
+ (instancetype) loadFromJsonFile:(NSString*)path;

/**
 Convert Server version into enumeration.
 */
+ (PowerAuthTestServerVersion) apiVersionFromString:(NSString*)stringVersion;

@end
