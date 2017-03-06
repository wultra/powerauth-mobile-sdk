/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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
#include <PowerAuthTests/PowerAuthTestsList.h>

using namespace cc7;

@interface PA2TestWrapper : XCTestCase
@end

@implementation PA2TestWrapper
{
	tests::TestManager * _manager;
}

- (void) dealloc
{
	tests::TestManager::releaseManager(_manager);
	_manager = nullptr;
}

- (void) setUp
{
	_manager = tests::TestManager::createDefaultManager();
	_manager->addUnitTestList(io::getlime::powerAuthTests::GetPowerAuthTestCreationInfoList());
	_manager->tl().setDumpToSystemLogEnabled(true);
	_manager->setLogCapturingEnabled(true);
}

- (void) tearDown
{
	tests::TestManager::releaseManager(_manager);
	_manager = nullptr;
}

- (BOOL)runTestWithFilter:(const char *)included excluded:(const char *)excluded testName:(const char*)name
{
	if (name) {
		_manager->setTestManagerName(std::string(name));
	}
	bool result = _manager->runTestsWithFilter(std::string(included), std::string(excluded));
	tests::TestLogData log_data = _manager->tl().logData();
	if (!result) {
		NSLog(@"Incidents:\n%@", [NSString stringWithUTF8String:log_data.incidents.c_str()]);
	}
	NSLog(@"Full test log:\n%@", [NSString stringWithUTF8String:log_data.log.c_str()]);

	return result;
}

- (void)testRunCC7Tests
{
	BOOL result = [self runTestWithFilter:"cc7" excluded:"" testName:nullptr];
	XCTAssertTrue(result);
}

- (void)testRunPA2Tests
{
	BOOL result = [self runTestWithFilter:"pa2" excluded:"" testName:"PowerAuth2.0"];
	XCTAssertTrue(result);
}

@end
