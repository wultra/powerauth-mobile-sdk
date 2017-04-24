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

- (id) initWithTestServerURL:(NSURL*)testServerUrl
			 applicationName:(NSString*)applicationName
		  applicationVersion:(NSString*)applicationVersion
{
	self = [super init];
	if (self) {
		_testServerUrl = testServerUrl;
		_applicationNameString = applicationName;
		_applicationVersionString = applicationVersion;
		
		NSBundle * mainBundle = [NSBundle bundleForClass:[self class]];
		NSURL * soapBundleUrl = [mainBundle URLForResource:@"SoapRequests" withExtension:@"bundle"];
		NSBundle * soapBundle = [NSBundle bundleWithURL:soapBundleUrl];
		
		_helper = [[SoapHelper alloc] initWithBundle:soapBundle url:testServerUrl];
	}
	return self;
}

- (BOOL) validateConnection
{
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
		if ([obj.applicationVersionName isEqualToString:_applicationVersionString]) {
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
	return YES;
}

#pragma mark - SOAP requests

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

PATSApplication * _XML_to_PATSApplication(CXMLNode * node, NSDictionary * ns, NSError ** localError)
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

PATSApplicationVersion * _XML_to_PATSApplicationVersion(CXMLNode * node, NSDictionary * ns, NSError ** localError)
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

- (PATSApplicationVersion*) createApplicationVersion:(NSString*)applicationId versionName:(NSString*)versionName
{
	PATSApplicationVersion * response = [_helper soapRequest:@"CreateApplicationVersion" params:@[applicationId, versionName] response:@"CreateApplicationVersionResponse" transform:^id(CXMLNode *resp, NSDictionary *ns) {
		NSError * localError = nil;
		PATSApplicationVersion * appVer = _XML_to_PATSApplicationVersion(resp, ns, &localError);
		return !localError ? appVer : nil;
	}];
	return response;
}

@end
