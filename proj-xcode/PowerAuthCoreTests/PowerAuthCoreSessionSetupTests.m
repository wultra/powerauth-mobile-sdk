/*
 * Copyright 2023 Wultra s.r.o.
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

#include <PowerAuthCore/PowerAuthCore.h>
#include <XCTest/XCTest.h>

@interface PowerAuthCoreSessionSetupTests : XCTestCase
@end

@implementation PowerAuthCoreSessionSetupTests
{
}

- (void) testSetupValidation
{
    BOOL result = [PowerAuthCoreSessionSetup validateConfiguration:@"ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA=="];
    XCTAssertTrue(result);
    result = [PowerAuthCoreSessionSetup validateConfiguration:@""];
    XCTAssertFalse(result);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    result = [PowerAuthCoreSessionSetup validateConfiguration:nil];
    XCTAssertFalse(result);
#pragma clang diagnostic pop
}

- (void) testConfigurationGenerator
{
    NSString * appKey = @"w4+hAeogFLTZjcSjPwbG2g==";
    NSString * appSecret = @"Szls/7JWbKN+FAOijHcsPA==";
    NSString * publicKey = @"BEEOwljSgItBIAnzr3f7K36s+KKoUzC8LE+K+7Dy0X6iAkcPXAjLP1KKPxdqyM/iihHAcW5x/WzJPCbtytcJo2w=";
    NSString * config = [PowerAuthCoreSessionSetup buildConfiguration:appKey appSecret:appSecret publicKey:publicKey];
    XCTAssertEqualObjects(@"ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", config);
}

@end
