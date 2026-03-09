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

#import <XCTest/XCTest.h>
#import "PowerAuthSdkTestHelper.h"

@interface BaseTestWithActivation : XCTestCase
{
    PowerAuthSDK * _sdk;
    PowerAuthSdkTestHelper * _helper;
}

@property (nonatomic, strong, readonly) PowerAuthSdkTestHelper * helper;
@property (nonatomic, strong, readonly) PowerAuthSDK * sdk;
@property (nonatomic, readonly) PowerAuthAlgorithm powerAuthAlgorithm;  // override in subclass
@property (nonatomic, readonly) BOOL supportsActivationWithSignature;
@property (nonatomic, readonly) BOOL hasBiometrySupport;

- (void) prepareConfigs:(PowerAuthConfiguration**)configuration
        biometricConfig:(PowerAuthBiometricConfiguration**)biometricConfiguration
         keychainConfig:(PowerAuthKeychainConfiguration**)keychainConfiguration
           clientConfig:(PowerAuthClientConfiguration**)clientConfiguration
            forTestName:(NSString*)testName;

- (void) reconfigureForTest:(NSString*)testName;

/// Contains YES if request failure simulator is available. This is typically YES only in DEBUG build.
@property (nonatomic, readonly) BOOL isRequestFailureSimulatorAvailable;

/// Simulate the next HTTP request failure for given path at non-200 response.
/// - Parameters:
///   - relativePath: Use `nil` or `"*"` to simulate failure for any next request.
///                   If path starts with `"/pa"` then use the path as is. If not,
///                   then function prepends the protocol version depending on the current
///                   test setup.
///   - statusCode: Status code to set for the response.
- (void) simulateNextResponseFailure:(NSString*)relativePath
                          statusCode:(NSInteger)statusCode;

/// Simulate the next HTTP request failure on network error, before data is sent to server.
/// - Parameters:
///   - relativePath: Use `nil` or `"*"` to simulate failure for any next request.
///                   If path starts with `"/pa"` then use the path as is. If not,
///                   then function prepends the protocol version depending on the current
///                   test setup.
- (void) simulateNetworkErrorOnSend:(NSString*)relativePath;

/// Simulate multiple consecutive HTTP request failure on network error, before data is sent to server.
/// - Parameters:
///   - relativePath: Use `nil` or `"*"` to simulate failure for any next request.
///                   If path starts with `"/pa"` then use the path as is. If not,
///                   then function prepends the protocol version depending on the current
///                   test setup.
///   - count: Number of consecutive HTTP requests that should fail.
- (void) simulateNetworkErrorOnSend:(NSString*)relativePath
                        repeatCount:(NSInteger)count;

/// Simulate the next HTTP request failure on network error, after data is successfully sent
/// to the server.
/// - Parameters:
///   - relativePath: Use `nil` or `"*"` to simulate failure for any next request.
///                   If path starts with `"/pa"` then use the path as is. If not,
///                   then function prepends the protocol version depending on the current
///                   test setup.
- (void) simulateNetworkErrorOnReceive:(NSString*)relativePath;

/// Clear all simulated HTTP failure hooks.
- (void) clearAllSimulateFailures;

@end

#pragma mark - Helper utilities

/**
 Checks whether the test config is valid. You should use this macro in all unit tests
 defined in this class.
 */
#define CHECK_TEST_CONFIG()     \
    if (!_sdk) {                \
        XCTFail(@"Test configuration is not valid.");   \
        return;                 \
    }

/**
 Checks boolean value in result local variable and returns |obj| value if contains NO.
 */
#define CHECK_RESULT_RET(obj)   \
    if (result == NO) {         \
        return obj;             \
    }

/**
  Checks whether biometry is available for testing.
 */
#define CHECK_BIOMETRY()        \
    if (![PowerAuthKeychain canUseBiometricAuthentication]) { \
        XCTFail(@"Biometric authentication is not available on this simulator. Please go to Device Simulator and make sure that `Features -> Face/Touch ID -> Enrolled` is ON"); \
        return;                 \
    }

