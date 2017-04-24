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

#import <XCTest/XCTest.h>
#import "PowerAuthTestServerAPI.h"

#ifndef POWERAUTH_TEST_SERVER_URL
#define POWERAUTH_TEST_SERVER_URL @"http://paserver:20010/powerauth-java-server/soap"
#endif

#ifndef POWERAUTH_TEST_SERVER_APP
#define POWERAUTH_TEST_SERVER_APP @"AutomaticTest-IOS"
#endif

#ifndef POWERAUTH_TEST_SERVER_APP_VERSION
#define POWERAUTH_TEST_SERVER_APP_VERSION @"default"
#endif

@interface PA2IntegrationTests : XCTestCase
@end

@implementation PA2IntegrationTests
{
	PowerAuthTestServerAPI * _testServerApi;
}

- (void)setUp
{
    [super setUp];
	
	if (!_testServerApi) {
		NSURL * testServerUrl = [NSURL URLWithString:POWERAUTH_TEST_SERVER_URL];
		_testServerApi = [[PowerAuthTestServerAPI alloc] initWithTestServerURL:testServerUrl
															   applicationName:POWERAUTH_TEST_SERVER_APP
															applicationVersion:POWERAUTH_TEST_SERVER_APP_VERSION];
		BOOL result = [_testServerApi validateConnection];
		XCTAssertTrue(result);
	}
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}


@end
