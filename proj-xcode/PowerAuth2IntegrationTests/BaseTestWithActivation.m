/*
 * Copyright 2025 Wultra s.r.o.
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

#import "BaseTestWithActivation.h"
// Access private SDK header
#import "../PowerAuth2/private/PA2CoreHttpClient.h"

@implementation BaseTestWithActivation

#pragma mark - Test setup

- (void)setUp
{
    [super setUp];
    [self clearAllSimulateFailures];
    [self reconfigureForTest:[PowerAuthSdkTestHelper currentTestNameFromTestCase:self]];
}

- (void) tearDown
{
    [self clearAllSimulateFailures];
    [_helper cleanup];
    [super tearDown];
}


- (void) prepareConfigs:(PowerAuthConfiguration**)configuration
        biometricConfig:(PowerAuthBiometricConfiguration**)biometricConfiguration
         keychainConfig:(PowerAuthKeychainConfiguration**)keychainConfiguration
           clientConfig:(PowerAuthClientConfiguration**)clientConfiguration
            forTestName:(NSString*)testName
{
    if ([testName isEqualToString:@"testCustomOfflineAuthCode"]) {
        (*configuration).offlineAuthenticationCodeComponentLength = 4;
    }
    (*configuration).algorithm = self.powerAuthAlgorithm;
}

- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_DEFAULT;
}

- (BOOL) supportsActivationWithSignature
{
    return self.powerAuthAlgorithm == PowerAuthAlgorithm_LEGACY_P256;
}

- (void) reconfigureForTest:(NSString *)testName
{
    _helper = [PowerAuthSdkTestHelper createCustom:^(PowerAuthConfiguration **configuration, PowerAuthBiometricConfiguration **biometricConfiguration, PowerAuthKeychainConfiguration **keychainConfiguration, PowerAuthClientConfiguration **clientConfiguration) {
        [self prepareConfigs:configuration biometricConfig:biometricConfiguration keychainConfig:keychainConfiguration clientConfig:clientConfiguration forTestName:testName];
    }];
    [_helper printConfig];
    _sdk = _helper.sdk;
    _helper.testServerApi.clientProtocolVersion = _sdk.currentAlgorithm == PowerAuthAlgorithm_LEGACY_P256 ? PATS_P33 : PATS_P40;
}

- (NSString*) patchRelativePathForSimulatedFailure:(NSString*)relativePath
{
    if (relativePath && ![relativePath isEqualToString:@"*"]) {
        if (![relativePath hasPrefix:@"/pa/"]) {
            // Adjust path depending on actual algorithm.
            XCTAssertTrue([relativePath hasPrefix:@"/"]);
            if ([self powerAuthAlgorithm] == PowerAuthAlgorithm_LEGACY_P256)  {
                relativePath = [@"/pa/v3" stringByAppendingString:relativePath];
            } else {
                relativePath = [@"/pa/v4" stringByAppendingString:relativePath];
            }
        }
    }
    return relativePath;
}

- (BOOL) isRequestFailureSimulatorAvailable
{
#if defined(DEBUG)
    return YES;
#else
    return NO;
#endif
}

- (void) simulateNextResponseFailure:(NSString*)relativePath
                          statusCode:(NSInteger)statusCode;
{
    XCTAssertNotEqual(200, statusCode);
#if defined(DEBUG)
    [PA2CoreHttpClient setNextResponseFailure:[self patchRelativePathForSimulatedFailure:relativePath]
                                   statusCode:statusCode];
#else
    XCTFail(@"Not available in release build");
#endif

}

- (void) simulateNetworkErrorOnSend:(NSString*)relativePath
{
#if defined(DEBUG)
    [self simulateNetworkErrorOnSend:relativePath repeatCount:1];
#else
    XCTFail(@"Not available in release build");
#endif
}

- (void) simulateNetworkErrorOnSend:(NSString*)relativePath
                        repeatCount:(NSInteger)count
{
    XCTAssertGreaterThan(count, 0);
#if defined(DEBUG)
    [PA2CoreHttpClient setNextRequestNetworkFailureOnSend:[self patchRelativePathForSimulatedFailure:relativePath] repeatCount:count];
#else
    XCTFail(@"Not available in release build");
#endif
}

- (void) simulateNetworkErrorOnReceive:(NSString*)relativePath
{
#if defined(DEBUG)
    [PA2CoreHttpClient setNextRequestNetworkFailureOnReceive:[self patchRelativePathForSimulatedFailure:relativePath]];
#else
    XCTFail(@"Not available in release build");
#endif
}

- (void) clearAllSimulateFailures
{
#if defined(DEBUG)
    [PA2CoreHttpClient clearAllFailureHooks];
#endif
}

@end
