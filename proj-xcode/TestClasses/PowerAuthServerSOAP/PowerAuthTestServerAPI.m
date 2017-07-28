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

#import "PowerAuthTestServerAPI.h"
#import "SoapHelper.h"

@implementation PowerAuthTestServerAPI
{
	NSURL * _testServerUrl;
	SoapHelper * _helper;
}

#pragma mark - Object initilization

- (id) initWithConfiguration:(PowerAuthTestServerConfig*)testServerConfig
{
	self = [super init];
	if (self) {
		_testServerUrl = [NSURL URLWithString:testServerConfig.soapApiUrl];
		_applicationNameString = testServerConfig.powerAuthAppName;
		_applicationVersionString = testServerConfig.powerAuthAppVersion;
		
		NSBundle * mainBundle = [NSBundle bundleForClass:[self class]];
		NSURL * soapBundleUrl = [mainBundle URLForResource:@"SoapRequests" withExtension:@"bundle"];
		NSBundle * soapBundle = [NSBundle bundleWithURL:soapBundleUrl];
		
		_helper = [[SoapHelper alloc] initWithBundle:soapBundle url:_testServerUrl];
	}
	return self;
}

- (BOOL) validateConnection
{
	_hasValidConnection = NO;
	
	PATSSystemStatus * systemStatus = [self getSystemStatus];
	if (![systemStatus.status isEqualToString:@"OK"]) {
		NSLog(@"System status is not OK, but '%@'", systemStatus.status);
		return NO;
	}
	
	NSArray<PATSApplication*>* applicationList = [self getApplicationList];
	__block PATSApplication * foundRequiredApp = nil;
	[applicationList enumerateObjectsUsingBlock:^(PATSApplication * app, NSUInteger idx, BOOL * stop) {
		if ([app.applicationName isEqualToString:_applicationNameString]) {
			foundRequiredApp = app;
			*stop = YES;
		}
	}];
	if (!foundRequiredApp) {
		// Version not found,
		foundRequiredApp = [self createApplication:_applicationNameString];
	}
	// Get Application detail
	_appDetail = [self getApplicationDetail:foundRequiredApp.applicationId];
	// Look for appropriate version
	[_appDetail.versions enumerateObjectsUsingBlock:^(PATSApplicationVersion * obj, NSUInteger idx, BOOL * stop) {
		if ([obj.applicationVersionName isEqualToString:_applicationVersionString] && obj.supported) {
			_appVersion = obj;
			*stop = YES;
		}
	}];
	//
	if (!_appVersion) {
		// We need to create requested app version
		_appVersion = [self createApplicationVersion:_appDetail.applicationId versionName:_applicationVersionString];
		
	}
	if (![_appDetail.applicationName isEqualToString:_applicationNameString]) {
		NSLog(@"Application name doesn't match: %@ vs %@", _appDetail.applicationName, _applicationNameString);
		return NO;
	}
	if (![_appVersion.applicationVersionName isEqualToString:_applicationVersionString]) {
		NSLog(@"Application version name doesn't match: %@ vs %@", _appVersion.applicationVersionName, _applicationVersionString);
		return NO;
	}
	
	_hasValidConnection = YES;
	
	return YES;
}

- (void) checkForValidConnection
{
	if (!_hasValidConnection) {
		@throw [NSException exceptionWithName:@"SoapError" reason:@"API object has no valid connection to the server." userInfo:nil];
	}
}

#pragma mark - System status

- (PATSSystemStatus*) getSystemStatus
{
	PATSSystemStatus * response = [_helper soapRequest:@"GetSystemStatus" params:nil response:@"GetSystemStatusResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSSystemStatus * obj = [[PATSSystemStatus alloc] init];
		if (!localError) obj.status					= [[resp nodeForXPath:@"pa:status" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.applicationName		= [[resp nodeForXPath:@"pa:applicationName" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.applicationDisplayName	= [[resp nodeForXPath:@"pa:applicationDisplayName" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.timestamp				= [[resp nodeForXPath:@"pa:timestamp" namespaceMappings:ns error:&localError] stringValue];
		return !localError ? obj : nil;
	}];
	return response;
}

#pragma mark - SOAP Application

static BOOL _BoolValue(CXMLNode * node)
{
	if (node) {
		NSString * strValue = [node stringValue];
		if ([strValue isEqualToString:@"true"]) {
			return YES;
		} else if ([strValue isEqualToString:@"false"]) {
			return NO;
		}
	}
	NSLog(@"Unable to convert XML boolean to BOOL");
	return NO;
	
}

////////////////////////////

static PATSApplication * _XML_to_PATSApplication(CXMLNode * node, NSDictionary * ns, NSError ** localError)
{
	PATSApplication * appObj = [[PATSApplication alloc] init];
	if (!*localError) appObj.applicationId   = [[node nodeForXPath:@"pa:id" namespaceMappings:ns error:localError] stringValue];
	if (!*localError) appObj.applicationName = [[node nodeForXPath:@"pa:applicationName" namespaceMappings:ns error:localError] stringValue];
	return appObj;
}

- (NSArray<PATSApplication*>*) getApplicationList
{
	NSArray * response = [_helper soapRequest:@"GetApplicationList" params:nil response:@"GetApplicationListResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		__block NSError * localError = nil;
		NSArray * xmlApps = [resp nodesForXPath:@"pa:applications" namespaceMappings:ns error:&localError];
		NSMutableArray * objApps = [NSMutableArray arrayWithCapacity:xmlApps.count];
		[xmlApps enumerateObjectsUsingBlock:^(CXMLNode * appNode, NSUInteger idx, BOOL * stop) {
			PATSApplication * appObj = _XML_to_PATSApplication(appNode, ns, &localError);
			if (!localError) {
				[objApps addObject:appObj];
			} else {
				*stop = YES;
			}
		}];
		return !localError ? objApps : nil;
	}];
	return response;
}

////////////////////////////

static PATSApplicationVersion * _XML_to_PATSApplicationVersion(CXMLNode * node, NSDictionary * ns, NSError ** localError)
{
	PATSApplicationVersion * verObj = [[PATSApplicationVersion alloc] init];
	if (!*localError) verObj.applicationVersionId	= [[node nodeForXPath:@"pa:applicationVersionId" namespaceMappings:ns error:localError] stringValue];
	if (!*localError) verObj.applicationVersionName	= [[node nodeForXPath:@"pa:applicationVersionName" namespaceMappings:ns error:localError] stringValue];
	if (!*localError) verObj.applicationKey			= [[node nodeForXPath:@"pa:applicationKey" namespaceMappings:ns error:localError] stringValue];
	if (!*localError) verObj.applicationSecret		= [[node nodeForXPath:@"pa:applicationSecret" namespaceMappings:ns error:localError] stringValue];
	if (!*localError) verObj.supported				= _BoolValue([node nodeForXPath:@"pa:supported" namespaceMappings:ns error:localError]);
	return verObj;
}

- (PATSApplicationDetail*) getApplicationDetail:(NSString*)applicationId
{
	PATSApplicationDetail * response = [_helper soapRequest:@"GetApplicationDetail" params:@[applicationId] response:@"GetApplicationDetailResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		__block NSError * localError = nil;
		PATSApplicationDetail * appObj = [[PATSApplicationDetail alloc] init];
		if (!localError) appObj.applicationId   = [[resp nodeForXPath:@"pa:applicationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) appObj.applicationName = [[resp nodeForXPath:@"pa:applicationName" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) appObj.masterPublicKey = [[resp nodeForXPath:@"pa:masterPublicKey" namespaceMappings:ns error:&localError] stringValue];
		
		NSArray * xmlVersions = [resp nodesForXPath:@"pa:versions" namespaceMappings:ns error:&localError];
		NSMutableArray<PATSApplicationVersion*>* objVersions = [NSMutableArray arrayWithCapacity:xmlVersions.count];
		[xmlVersions enumerateObjectsUsingBlock:^(CXMLNode * verNode, NSUInteger idx, BOOL * stop) {
			PATSApplicationVersion * verObj = _XML_to_PATSApplicationVersion(verNode, ns, &localError);
			if (!localError) {
				[objVersions addObject:verObj];
			} else {
				*stop = YES;
			}
		}];
		if (!localError) appObj.versions = objVersions;
		return !localError ? appObj : nil;
	}];
	return response;
}

- (PATSApplication*) createApplication:(NSString*)applicationName
{
	PATSApplication * response = [_helper soapRequest:@"CreateApplication" params:@[applicationName] response:@"CreateApplicationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSApplication * appObj = _XML_to_PATSApplication(resp, ns, &localError);
		return !localError ? appObj : nil;
	}];
	return response;
}

#pragma mark - SOAP Application Versions

- (PATSApplicationVersion*) createApplicationVersion:(NSString*)applicationId versionName:(NSString*)versionName
{
	PATSApplicationVersion * response = [_helper soapRequest:@"CreateApplicationVersion" params:@[applicationId, versionName] response:@"CreateApplicationVersionResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSApplicationVersion * appVer = _XML_to_PATSApplicationVersion(resp, ns, &localError);
		return !localError ? appVer : nil;
	}];
	return response;
}

- (PATSApplicationVersion*) createApplicationVersionIfDoesntExist:(NSString*)versionName
{
	[self checkForValidConnection];
	// Update app detail
	_appDetail = [self getApplicationDetail:_appDetail.applicationId];
	// Look for version
	__block PATSApplicationVersion * response = nil;
	[_appDetail.versions enumerateObjectsUsingBlock:^(PATSApplicationVersion * obj, NSUInteger idx, BOOL * stop) {
		if ([obj.applicationVersionId isEqualToString:versionName]) {
			if (obj.supported) {
				response = obj;
				*stop = YES;
			}
		}
	}];
	if (!response) {
		response = [self createApplicationVersion:_appDetail.applicationId versionName:versionName];
	}
	return response;
}

- (BOOL) supportApplicationVersion:(NSString*)applicationVersionId
{
	PATSApplicationVersionSupport * response = [_helper soapRequest:@"SupportApplicationVersion" params:@[applicationVersionId] response:@"SupportApplicationVersionResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSApplicationVersionSupport * obj = [[PATSApplicationVersionSupport alloc] init];
		if (!localError) obj.applicationVersionId	= [[resp nodeForXPath:@"pa:applicationVersionId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.supported				= _BoolValue([resp nodeForXPath:@"pa:supported" namespaceMappings:ns error:&localError]);
		return !localError ? obj : nil;
	}];
	BOOL result = response.supported == YES;
	if (!result) {
		NSLog(@"Changing version '%@' status to 'supported' failed.", applicationVersionId);
	}
	return result;
}

- (BOOL) unsupportApplicationVersion:(NSString*)applicationVersionId
{
	PATSApplicationVersionSupport * response = [_helper soapRequest:@"UnsupportApplicationVersion" params:@[applicationVersionId] response:@"UnsupportApplicationVersionResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSApplicationVersionSupport * obj = [[PATSApplicationVersionSupport alloc] init];
		if (!localError) obj.applicationVersionId	= [[resp nodeForXPath:@"pa:applicationVersionId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.supported				= _BoolValue([resp nodeForXPath:@"pa:supported" namespaceMappings:ns error:&localError]);
		return !localError ? obj : nil;
	}];
	BOOL result = response.supported == NO;
	if (!result) {
		NSLog(@"Changing version '%@' status to 'unsupported' failed.", applicationVersionId);
	}
	return result;
}

#pragma mark - SOAP Activation

- (PATSInitActivationResponse*) initializeActivation:(NSString *)userId
{
	[self checkForValidConnection];
	PATSInitActivationResponse * response = [_helper soapRequest:@"InitActivation" params:@[userId, _appDetail.applicationId] response:@"InitActivationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSInitActivationResponse * obj = [[PATSInitActivationResponse alloc] init];
		if (!localError) obj.activationId			= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationIdShort		= [[resp nodeForXPath:@"pa:activationIdShort" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationOTP			= [[resp nodeForXPath:@"pa:activationOTP" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationSignature	= [[resp nodeForXPath:@"pa:activationSignature" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.userId					= [[resp nodeForXPath:@"pa:userId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.applicationId			= [[resp nodeForXPath:@"pa:applicationId" namespaceMappings:ns error:&localError] stringValue];
		return !localError ? obj : nil;
	}];
	return response;
}

- (BOOL) removeActivation:(NSString*)activationId
{
	[self checkForValidConnection];
	NSDictionary * response = [_helper soapRequest:@"RemoveActivation" params:@[activationId] response:@"RemoveActivationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		NSMutableDictionary * obj = [NSMutableDictionary dictionaryWithCapacity:2];
		if (!localError) obj[@"activationId"]		= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj[@"removed"]			= @(_BoolValue([resp nodeForXPath:@"pa:removed" namespaceMappings:ns error:&localError]));
		return !localError ? obj : nil;
	}];
	if (![response[@"removed"] boolValue]) {
		NSLog(@"The requested activation '%@' was not removed.", activationId);
		return NO;
	}
	return YES;
}

static PATSActivationStatusEnum _String_to_ActivationStatusEnum(NSString * str)
{
	if ([str isEqualToString:@"CREATED"]) {
		return PATSActivationStatus_CREATED;
	} else if ([str isEqualToString:@"OTP_USED"]) {
		return PATSActivationStatus_OTP_USED;
	} else if ([str isEqualToString:@"ACTIVE"]) {
		return PATSActivationStatus_ACTIVE;
	} else if ([str isEqualToString:@"BLOCKED"]) {
		return PATSActivationStatus_BLOCKED;
	} else if ([str isEqualToString:@"REMOVED"]) {
		return PATSActivationStatus_REMOVED;
	}
	return PATSActivationStatus_Unknown;
}

- (PATSActivationStatus*) getActivationStatus:(NSString*)activationId
{
	[self checkForValidConnection];
	PATSActivationStatus * response = [_helper soapRequest:@"GetActivationStatus" params:@[activationId] response:@"GetActivationStatusResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSActivationStatus * obj = [[PATSActivationStatus alloc] init];
		if (!localError) obj.activationId			= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatus		= [[resp nodeForXPath:@"pa:activationStatus" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatusEnum	= _String_to_ActivationStatusEnum(obj.activationStatus);
		if (!localError) obj.activationName			= [[resp nodeForXPath:@"pa:activationName" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.userId					= [[resp nodeForXPath:@"pa:userId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.applicationId			= [[resp nodeForXPath:@"pa:applicationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.timestampCreated		= [[resp nodeForXPath:@"pa:timestampCreated" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.timestampLastUsed		= [[resp nodeForXPath:@"pa:timestampLastUsed" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.encryptedStatusBlob	= [[resp nodeForXPath:@"pa:encryptedStatusBlob" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.devicePublicKeyFingerprint = [[resp nodeForXPath:@"pa:devicePublicKeyFingerprint" namespaceMappings:ns error:&localError] stringValue];
		return !localError ? obj : nil;
	}];
	return response;
}

- (PATSSimpleActivationStatus*) blockActivation:(NSString*)activationId
{
	[self checkForValidConnection];
	PATSSimpleActivationStatus * response = [_helper soapRequest:@"BlockActivation" params:@[activationId] response:@"BlockActivationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSSimpleActivationStatus * obj = [[PATSActivationStatus alloc] init];
		if (!localError) obj.activationId			= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatus		= [[resp nodeForXPath:@"pa:activationStatus" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatusEnum	= _String_to_ActivationStatusEnum(obj.activationStatus);
		return !localError ? obj : nil;
	}];
	return response;
}

- (PATSSimpleActivationStatus*) unblockActivation:(NSString*)activationId;
{
	[self checkForValidConnection];
	PATSSimpleActivationStatus * response = [_helper soapRequest:@"UnblockActivation" params:@[activationId] response:@"UnblockActivationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSSimpleActivationStatus * obj = [[PATSActivationStatus alloc] init];
		if (!localError) obj.activationId			= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatus		= [[resp nodeForXPath:@"pa:activationStatus" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj.activationStatusEnum	= _String_to_ActivationStatusEnum(obj.activationStatus);
		return !localError ? obj : nil;
	}];
	return response;
}

- (BOOL) commitActivation:(NSString*)activationId
{
	[self checkForValidConnection];
	NSDictionary * response = [_helper soapRequest:@"CommitActivation" params:@[activationId] response:@"CommitActivationResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		NSMutableDictionary * obj = [NSMutableDictionary dictionaryWithCapacity:2];
		if (!localError) obj[@"activationId"]		= [[resp nodeForXPath:@"pa:activationId" namespaceMappings:ns error:&localError] stringValue];
		if (!localError) obj[@"activated"]			= @(_BoolValue([resp nodeForXPath:@"pa:activated" namespaceMappings:ns error:&localError]));
		return !localError ? obj : nil;
	}];
	if (![response[@"activated"] boolValue]) {
		NSLog(@"The requested activation '%@' was not commited.", activationId);
		return NO;
	}
	return YES;
}

#pragma mark - SOAP Signatures

- (BOOL) verifyECDSASignature:(NSString*)activationId data:(NSData*)data signature:(NSData*)signature
{
	NSString * dataB64 = [data base64EncodedStringWithOptions:0];
	NSString * signatureB64 = [signature base64EncodedStringWithOptions:0];
	
	NSDictionary * response = [_helper soapRequest:@"VerifyECDSASignature" params:@[activationId, dataB64, signatureB64] response:@"VerifyECDSASignatureResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		NSMutableDictionary * obj = [NSMutableDictionary dictionaryWithCapacity:2];
		if (!localError) obj[@"signatureValid"] = @(_BoolValue([resp nodeForXPath:@"pa:signatureValid" namespaceMappings:ns error:&localError]));
		return !localError ? obj : nil;
	}];
	return [response[@"signatureValid"] boolValue];
}


@end
