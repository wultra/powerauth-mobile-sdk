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

#import "PowerAuthSDKDefaultTests.h"

@interface PowerAuthSDKSharedTests : PowerAuthSDKDefaultTests
@end

@implementation PowerAuthSDKSharedTests

- (void) prepareConfigs:(PowerAuthConfiguration *)configuration
		 keychainConfig:(PowerAuthKeychainConfiguration *)keychainConfiguration
		   clientConfig:(PowerAuthClientConfiguration *)clientConfiguration
{
	configuration.instanceId = @"SharedInstanceTests";
	PowerAuthSharingConfiguration * sharingConfig = [[PowerAuthSharingConfiguration alloc] initWithAppGroup:@"com.dummyGroup" appIdentifier:@"appInstance_1"];
	configuration.sharingConfiguration = sharingConfig;
}

@end
