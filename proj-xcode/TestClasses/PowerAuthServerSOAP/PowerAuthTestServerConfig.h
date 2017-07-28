/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
 The `PowerAuthTestServerConfig` object contains a configuration required for inregration
 testing. You can create a default config, or load it from JSON file.
 */
@interface PowerAuthTestServerConfig : NSObject

/**
 String with URL to REST API
 */
@property (nonatomic, strong, readonly) NSString * restApiUrl;
/**
 String with URL to SOAP API
 */
@property (nonatomic, strong, readonly) NSString * soapApiUrl;
/**
 A name for application, which will be used on the PA2 server.
 If nil, then @"AutomaticTest-IOS" is used.
 */
@property (nonatomic, strong, readonly) NSString * powerAuthAppName;
/**
 An application's version name used on the PA2 server. 
 If nil, then @"default" is used.
 */
@property (nonatomic, strong, readonly) NSString * powerAuthAppVersion;

/**
 Creates a default configuration for a server, placed at "http://paserver" base domain.
 */
+ (instancetype) defaultConfig;

/**
 Creates a configuration from given JSON file.
 */
+ (instancetype) loadFromJsonFile:(NSString*)path;

@end
