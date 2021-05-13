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

#import <XCTest/XCTest.h>
#import <PowerAuthCore/PowerAuthCore.h>

#import "PowerAuthCorePrivateImpl.h"

/*
 This file contains mostly simple unit tests for ObjC objects using
 C++ core structures as internal model objects.
 Typically, we need to test if the ObjC property is properly mapped
 to the right C++ structure member.
 */

using namespace io::getlime::powerAuth;

@interface PowerAuthCorePublicObjectsTests : XCTestCase
@end

@implementation PowerAuthCorePublicObjectsTests

- (void) testPowerAuthCoreSignedData
{
	const char hello[] = "HELLO WORLD!";
	const char magic[] = "THIS IS MAGIC";
	NSData * hello_obj = [NSData dataWithBytes:hello length:sizeof(hello)-1];
	NSData * magic_obj = [NSData dataWithBytes:magic length:sizeof(magic)-1];
	
	PowerAuthCoreSignedData * sd = [[PowerAuthCoreSignedData alloc] init];
	XCTAssertTrue(sd.data.length == 0);
	XCTAssertTrue(sd.signature.length == 0);
	XCTAssertTrue(sd.dataBase64.length == 0);
	XCTAssertTrue(sd.dataBase64.length == 0);
	XCTAssertNotNil(sd.data);
	XCTAssertNotNil(sd.signature);
	XCTAssertNotNil(sd.dataBase64);
	XCTAssertNotNil(sd.signatureBase64);
	
	// change in binary property must be properly mapped to base64 and vice versa.
	sd.data = hello_obj;
	XCTAssertTrue([sd.dataBase64 isEqualToString:@"SEVMTE8gV09STEQh"]);
	sd.signature = hello_obj;
	XCTAssertTrue([sd.dataBase64 isEqualToString:@"SEVMTE8gV09STEQh"]);
	
	sd.dataBase64 = @"VEhJUyBJUyBNQUdJQw==";
	XCTAssertTrue([sd.data isEqualToData:magic_obj]);
	sd.signatureBase64 = @"VEhJUyBJUyBNQUdJQw==";
	XCTAssertTrue([sd.signature isEqualToData:magic_obj]);
}

- (void) testPowerAuthActivationStatus
{
	NSArray * pa2statuses = @[@(PowerAuthCoreActivationState_Created), @(PowerAuthCoreActivationState_PendingCommit),
							  @(PowerAuthCoreActivationState_Active), @(PowerAuthCoreActivationState_Blocked),
							  @(PowerAuthCoreActivationState_Removed)];
	static ActivationStatus::State coreStates[] = { ActivationStatus::Created, ActivationStatus::PendingCommit,
													ActivationStatus::Active, ActivationStatus::Blocked,
													ActivationStatus::Removed };
	
	[pa2statuses enumerateObjectsUsingBlock:^(NSNumber * pa2st, NSUInteger idx, BOOL * stop) {
		ActivationStatus cpp_status;
		cpp_status.failCount = (cc7::U32)idx;
		cpp_status.maxFailCount = (cc7::U32)(100 - idx);
		cpp_status.state = coreStates[idx];
		cpp_status.currentVersion = ActivationStatus::V2;
		cpp_status.upgradeVersion = ActivationStatus::V3;
		
		PowerAuthCoreActivationStatus * so = PowerAuthCoreActivationStatusToObject(cpp_status);
		XCTAssertEqual(so.state, (PowerAuthCoreActivationState)pa2st.integerValue);
		XCTAssertEqual(so.maxFailCount, 100 - idx);
		XCTAssertEqual(so.failCount, idx);
		XCTAssertEqual(so.currentActivationVersion, 2);
		XCTAssertEqual(so.upgradeActivationVersion, 3);
	}];
}

- (void) testPowerAuthCoreHTTPRequestDataSignature
{
	PowerAuthCoreHTTPRequestDataSignature * signature = [[PowerAuthCoreHTTPRequestDataSignature alloc] init];
	HTTPRequestDataSignature& ref = signature.signatureStructRef;
	ref.activationId = "activation-id";
	ref.applicationKey = "hello world";
	ref.version = "3.0";
	ref.nonce = "nonce";
	ref.factor = "possession";
	ref.signature = "00000000";
	
	XCTAssertTrue([signature.activationId isEqualToString:@"activation-id"]);
	XCTAssertTrue([signature.applicationKey isEqualToString:@"hello world"]);
	XCTAssertTrue([signature.version isEqualToString:@"3.0"]);
	XCTAssertTrue([signature.nonce isEqualToString:@"nonce"]);
	XCTAssertTrue([signature.factor isEqualToString:@"possession"]);
	XCTAssertTrue([signature.signature isEqualToString:@"00000000"]);
	
	NSString * validHdr = @"PowerAuth pa_version=\"3.0\", pa_activation_id=\"activation-id\","
						  @" pa_application_key=\"hello world\", pa_nonce=\"nonce\","
						  @" pa_signature_type=\"possession\", pa_signature=\"00000000\"";
	XCTAssertTrue([signature.authHeaderValue isEqualToString:validHdr]);
}

@end
