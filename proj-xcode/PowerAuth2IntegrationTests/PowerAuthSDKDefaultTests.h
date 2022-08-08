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
#import "PowerAuthSdkTestHelper.h"

/**
 The purpose of `PowerAuthSDKTests` is to run a series of integration tests where the
 high level `PowerAuthSDK` class is a primary test subject. All integration tests
 needs a running server as a counterpart and therefore are by-default disabled for all
 main development schemas ("PA2_Release", "PA2_Debug"). To run this test, you
 need to switch to "PA2_IntegrationTests" scheme and create a configuration.
 Check 'TestConfig/Readme.md' for details.
 */
@interface PowerAuthSDKDefaultTests : XCTestCase

@property (nonatomic, strong, readonly) PowerAuthSdkTestHelper * helper;
@property (nonatomic, strong, readonly) PowerAuthSDK * sdk;

- (void) prepareConfigs:(PowerAuthConfiguration*)configuration
         keychainConfig:(PowerAuthKeychainConfiguration*)keychainConfiguration
           clientConfig:(PowerAuthClientConfiguration*)clientConfiguration;

@end
