/**
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
#import "PA2SessionStatusDataReader.h"

@interface PowerAuth2ForExtensionsTests : XCTestCase
@end

@implementation PowerAuth2ForExtensionsTests

- (void) testActivationIdExtraction
{
    // V2 data
    NSString * serializedDataV2 = @"UEECUDMAAAAAAAACChtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAACcQEFxD134A7"
                                  @"jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwGrtEGAsKs9Rh8"
                                  @"mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+eahxi9n7A4ajz"
                                  @"LgtaC3tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQybj5WeD2HhFLw"
                                  @"EJr1nHvmSQAAAAA=";
    NSData * dataV2 = [[NSData alloc] initWithBase64EncodedString:serializedDataV2 options:0];
    XCTAssertNotNil(dataV2);
    NSString * activationIdV2 = PA2SessionStatusDataReader_GetActivationId(dataV2);
    XCTAssertEqualObjects(@"FULL-BUT-FAKE-ACTIVATION-ID", activationIdV2);
    
    // V3 data
    NSString * serializedDataV3 = @"UEECUDQQcXKzF7KLEfVzcb6F7dQ2jhtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAACcQEFx"
                                  @"D134A7jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwGrtEGAsKs9Rh8"
                                  @"mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+eahxi9n7A4ajzLgtaC3"
                                  @"tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQybj5WeD2HhFLwEJr1nHvmSQAA"
                                  @"AAA=";
    NSData * dataV3 = [[NSData alloc] initWithBase64EncodedString:serializedDataV3 options:0];
    XCTAssertNotNil(dataV3);
    NSString * activationIdV3 = PA2SessionStatusDataReader_GetActivationId(dataV3);
    XCTAssertEqualObjects(@"FULL-BUT-FAKE-ACTIVATION-ID", activationIdV3);
    
    // V4, V5 data
    NSString * serializedDataV4 = @"UEECUDUQcXKzF7KLEfVzcb6F7dQ2jhtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAA"
                                  @"CcQEFxD134A7jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwG"
                                  @"rtEGAsKs9Rh8mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+e"
                                  @"ahxi9n7A4ajzLgtaC3tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQy"
                                  @"bj5WeD2HhFLwEJr1nHvmSQAAAAAA";
    NSData * dataV4 = [[NSData alloc] initWithBase64EncodedString:serializedDataV4 options:0];
    XCTAssertNotNil(dataV4);
    NSString * activationIdV4 = PA2SessionStatusDataReader_GetActivationId(dataV4);
    XCTAssertEqualObjects(@"FULL-BUT-FAKE-ACTIVATION-ID", activationIdV4);
    
    // V6 data
    NSString * serializedDataV6 = @"UEECUDYQf14TA2IN0N6VoDJBjilDQiRkNGE3ZjcyMy0wYjVkLTRkNmYtYjUyMS0yNWUwOTUxO"
                                  @"TVjZGQAACcQEK2Ay+gcAT"@"0myjKGsC+zBRQQVoUVjmQJ2QPYnmurcQglvhCFZN4BPPLGGYs"
                                  @"3WGQWPsUwABBdozK+8+yg8a0j5VHZ3hG0QQTYhwy+miVeI2RQL3bKcIggp02t6w6bQo5GrO4z"
                                  @"LBJeNUTk3S2rF87fT2Cw8jf4f1E+u0D4hBFdrzuXF7gMyPIbIQKoHBeEqkdBXw5DwmEtJ/PQi"
                                  @"tb3PFDhNh3cs93m3ugZ/jD2xuXr14Akc3Tzea8DDKfGARXHl/rPI/sce31zaQac9ERngH8nhB"
                                  @"ZKLmYqgzfYEvwAAAQAAAA=";
    NSData * dataV6 = [[NSData alloc] initWithBase64EncodedString:serializedDataV6 options:0];
    XCTAssertNotNil(dataV6);
    NSString * activationIdV6 = PA2SessionStatusDataReader_GetActivationId(dataV6);
    XCTAssertEqualObjects(@"d4a7f723-0b5d-4d6f-b521-25e095195cdd", activationIdV6);
}

@end
