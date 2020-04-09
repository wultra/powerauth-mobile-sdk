/**
 * Copyright 2017 Wultra s.r.o.
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

#import "SoapHelper.h"
#import "AsyncHelper.h"
#import "CXMLDocument.h"


@implementation SoapHelper
{
	NSBundle * _bundle;
	NSURL * _url;
	NSMutableDictionary * _cache;
	PowerAuthTestServerVersion _version;
	NSDictionary<NSString*, SoapHelperMapping*>* _templateMapping;
}

- (id) initWithBundle:(NSBundle*)bundle
			   config:(PowerAuthTestServerConfig*)config
{
	self = [super init];
	if (self) {
		_bundle = bundle;
		_url = [NSURL URLWithString:config.soapApiUrl];
		_version = config.soapApiVersion;
		_cache = [NSMutableDictionary dictionary];
		_session = [NSURLSession sharedSession];
		if (_version == PATS_V0_24) {
			_templateMapping = [SoapHelper mappingForV0_24];
		} else if (_version == PATS_V0_23_2) {
			_templateMapping = [SoapHelper mappingForV0_23_2];
		} else if (_version == PATS_V0_23) {
			_templateMapping = [SoapHelper mappingForV0_23];
		} else if (_version == PATS_V0_22_2) {
			_templateMapping = [SoapHelper mappingForV0_22_2];
		} else if (_version == PATS_V0_22) {
			_templateMapping = [SoapHelper mappingForV0_22];
		} else {
			@throw [NSException exceptionWithName:@"SoapError" reason:@"Connection to V2 server is not supported." userInfo:nil];
		}
	}
	return self;
}

- (id) soapRequest:(NSString*)requestName
			  params:(NSArray*)params
			response:(NSString*)responseNodeName
		   transform:(id (^)(CXMLNode * soapBody, NSDictionary * xmlNamespaceMapping))transformBlock
{
	SoapHelperMapping * mapping = _templateMapping[requestName];
	if (!mapping) {
		@throw [NSException exceptionWithName:@"SoapError" reason:@"Unknown mapping for SOAP envelope." userInfo:nil];
	}
	NSString * envelopeData = [self formatEnvelope:requestName mapping:mapping params:params];
	if (!envelopeData) {
		@throw [NSException exceptionWithName:@"SoapError" reason:@"Unable to format SOAP envelope." userInfo:nil];
	}
	
	// Prepare xml namespaces
	NSDictionary * xmlNamespaceMapping =
  	@{
		@"soap" : @"http://schemas.xmlsoap.org/soap/envelope/",
		@"pa"   : mapping.xmlns
	};
	
	// Make things synchronous
	__block id responseObject = nil;
	__block NSError * responseError = nil;
	
	[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		//NSLog(@"Envelope data %@", envelopeData);
		// Prepare request
		NSMutableURLRequest * request = [NSMutableURLRequest requestWithURL:_url];
		request.HTTPMethod = @"POST";
		request.HTTPBody = [envelopeData dataUsingEncoding:NSUTF8StringEncoding];
		[request setValue:@"text/xml;charset=UTF-8" forHTTPHeaderField:@"Content-Type"];
		//
		NSURLSessionDataTask * task = [_session dataTaskWithRequest:request completionHandler:^(NSData * data, NSURLResponse * response, NSError * error) {
			if (data && !error) {
				CXMLDocument * document = [[CXMLDocument alloc] initWithData:data options:0 error:&error];
				if (!error && document) {
					CXMLNode * bodyNode = [self lookForSoapBodyNode:document xmlNamespaceMapping:xmlNamespaceMapping responseNode:responseNodeName error:&error];
					if (!error && bodyNode) {
						// Report SOAP body node
						responseObject = transformBlock(bodyNode, xmlNamespaceMapping);
						if (responseObject) {
							[waiting reportCompletion:nil];
							return;
						}
						NSDictionary * info = @{ NSLocalizedDescriptionKey : @"XML to Object transformation returned nil." } ;
						error = [NSError errorWithDomain:@"SoapError" code:1 userInfo:info];
					}
				}
			}
			if (!error) {
				NSDictionary * info = @{ NSLocalizedDescriptionKey : @"Unknown error during SOAP response processing." } ;
				error = [NSError errorWithDomain:@"SoapError" code:1 userInfo:info];
			}
			responseError = error;
			[waiting reportCompletion:nil];
		}];
		[task resume];
	}];
	// Process result
	if (responseError) {
		@throw [NSException exceptionWithName:@"SoapError" reason:responseError.localizedDescription userInfo:nil];
	}
	return responseObject;
}

/*
 Returns CXMLNode, representing body in SOAP message from given |xmlDocument|. If there's failure, then stores
 NSError object to |error| pointer. The body node's name must be equal to |responseNode| string.
 */
- (CXMLNode*) lookForSoapBodyNode:(CXMLDocument*)xmlDocument
			  xmlNamespaceMapping:(NSDictionary*)xmlNamespaceMapping
					 responseNode:(NSString*)responseNode
							error:(NSError**)error
{
	NSError * localError = nil;
	CXMLElement * root = xmlDocument.rootElement;
	CXMLNode * fault = [root nodeForXPath:@"/soap:Envelope/soap:Body/soap:Fault" namespaceMappings:xmlNamespaceMapping error:&localError];
	if (fault) {
		NSString * faultMessage = [fault nodeForXPath:@"faultstring" namespaceMappings:xmlNamespaceMapping error:&localError].stringValue;
		if (!faultMessage) {
			faultMessage = @"Unknown failure received from server. XML is valid, but there's no string value for error";
		}
		localError = [NSError errorWithDomain:@"SoapError" code:1 userInfo:@{NSLocalizedDescriptionKey:faultMessage}];
	}
	if (!localError) {
		CXMLNode * responseBody = [[root nodesForXPath:@"/soap:Envelope/soap:Body" namespaceMappings:xmlNamespaceMapping error:&localError] firstObject];
		CXMLNode * responseObject = [responseBody.children firstObject];
		if (responseObject) {
			if ([responseObject.localName isEqualToString:responseNode]) {
				return responseObject;
			}
			NSString * faultMessage = [NSString stringWithFormat:@"The response doesn't containt element with name '%@'", responseNode];
			localError = [NSError errorWithDomain:@"SoapError" code:1 userInfo:@{NSLocalizedDescriptionKey:faultMessage}];
		}
	}
	if (!localError) {
		NSString * faultMessage = @"XML response processing failed";
		localError = [NSError errorWithDomain:@"SoapError" code:1 userInfo:@{NSLocalizedDescriptionKey:faultMessage}];
	}
	if (error) {
		*error = localError;
	}
	return nil;
}

/*
 Returns a SOAP envelope (the whole XML string with HTTP POST request payload)
 */
- (NSString*) formatEnvelope:(NSString*)templateName
					 mapping:(SoapHelperMapping*)mapping
					  params:(NSArray*)params
{
	// 1) Look for template string
	NSString * templateString = [_cache objectForKey:templateName];
	if (!templateString) {
		// Load XML template from bundle
		NSString * path = [_bundle pathForResource:mapping.envelopePath ofType:@"xml"];
		if (!path) {
			NSLog(@"Requested SOAP template doesn't exist");
			return nil;
		}
		NSData * templateData = [[NSData alloc] initWithContentsOfFile:path];
		templateString = [[NSString alloc] initWithData:templateData encoding:NSUTF8StringEncoding];
		if (!templateData || !templateString) {
			NSLog(@"Can't load data for SOAP template: %@", path);
			return nil;
		}
		// Store to cache
		[_cache setObject:templateString forKey:templateName];
	}
	// 2) Remplace $XMLNS with xmlns value
	templateString = [templateString stringByReplacingOccurrencesOfString:@"$XMLNS" withString:mapping.xmlns];
	
	// 3) Replace all $X placeholders with values from params array
	for (NSUInteger index = 0; index < params.count; index++) {
		id pobj = params[index];
		NSString * pstr;
		if ([pobj isKindOfClass:[NSString class]]) {
			pstr = pobj;
		} else {
			pstr = [pobj stringValue];
		}
		// Escape important XML entities
		pstr = [[[[[pstr stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"]
				   stringByReplacingOccurrencesOfString:@"\"" withString:@"&quot;"]
				  stringByReplacingOccurrencesOfString:@"'" withString:@"&#39;"]
					stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"]
				stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
		
		NSString * pholder = [@"$" stringByAppendingString:[@(index + 1) stringValue]];
		templateString = [templateString stringByReplacingOccurrencesOfString:pholder withString:pstr];
	}
	return templateString;
}

#pragma mark - Mappings for various server methods

#define MAP(ns, path) [SoapHelperMapping map:@[ns, path]]

+ (NSDictionary<NSString*, SoapHelperMapping*>*) mappingForV0_22
{
	NSString * v3 = @"http://getlime.io/security/powerauth/v3";
	return @{
			 @"BlockActivation" 				: MAP(v3, @"BlockActivation"),
			 @"CommitActivation" 				: MAP(v3, @"CommitActivation"),
			 @"CreateApplication" 				: MAP(v3, @"CreateApplication"),
			 @"CreateApplicationVersion" 		: MAP(v3, @"CreateApplicationVersion"),
			 @"CreateNonPersonalizedOfflineSignaturePayload": MAP(v3, @"CreateNonPersonalizedOfflineSignaturePayload"),
			 @"CreatePersonalizedOfflineSignaturePayload"	: MAP(v3, @"CreatePersonalizedOfflineSignaturePayload"),
			 @"CreateToken"						: MAP(v3, @"_v3/CreateToken"),
			 @"GetActivationStatus"				: MAP(v3, @"GetActivationStatus"),
			 @"GetApplicationDetail"			: MAP(v3, @"GetApplicationDetail"),
			 @"GetApplicationList"				: MAP(v3, @"GetApplicationList"),
			 @"GetSystemStatus"					: MAP(v3, @"GetSystemStatus"),
			 @"InitActivation"					: MAP(v3, @"InitActivation"),
			 @"RemoveActivation"				: MAP(v3, @"RemoveActivation"),
			 @"RemoveToken"						: MAP(v3, @"RemoveToken"),
			 @"SupportApplicationVersion"		: MAP(v3, @"SupportApplicationVersion"),
			 @"UnblockActivation"				: MAP(v3, @"UnblockActivation"),
			 @"UnsupportApplicationVersion"		: MAP(v3, @"UnsupportApplicationVersion"),
			 @"ValidateToken"					: MAP(v3, @"ValidateToken"),
			 @"VerifyECDSASignature"			: MAP(v3, @"VerifyECDSASignature"),
			 @"VerifyOfflineSignature"			: MAP(v3, @"VerifyOfflineSignature"),
			 @"VerifySignature"					: MAP(v3, @"_v3/VerifySignature"),	// Default signature validation (without specified version)
			 @"VerifySignature_ForceVer"		: MAP(v3, @"_v3/VerifySignature_ForceVer"),	// The same template, but with additional "forcedSignatureVersion" param
			 };
}

+ (NSDictionary<NSString*, SoapHelperMapping*>*) mappingForV0_22_2
{
	NSString * v3 = @"http://getlime.io/security/powerauth/v3";
	return @{
			 @"BlockActivation" 				: MAP(v3, @"BlockActivation"),
			 @"CommitActivation" 				: MAP(v3, @"CommitActivation"),
			 @"CreateApplication" 				: MAP(v3, @"CreateApplication"),
			 @"CreateApplicationVersion" 		: MAP(v3, @"CreateApplicationVersion"),
			 @"CreateNonPersonalizedOfflineSignaturePayload": MAP(v3, @"CreateNonPersonalizedOfflineSignaturePayload"),
			 @"CreatePersonalizedOfflineSignaturePayload"	: MAP(v3, @"CreatePersonalizedOfflineSignaturePayload"),
			 @"CreateToken"						: MAP(v3, @"_v3/CreateToken"),
			 @"GetActivationStatus"				: MAP(v3, @"GetActivationStatus"),
			 @"GetApplicationDetail"			: MAP(v3, @"GetApplicationDetail"),
			 @"GetApplicationList"				: MAP(v3, @"GetApplicationList"),
			 @"GetSystemStatus"					: MAP(v3, @"GetSystemStatus"),
			 @"InitActivation"					: MAP(v3, @"InitActivation"),
			 @"RemoveActivation"				: MAP(v3, @"RemoveActivation_Revoke"),
			 @"RemoveToken"						: MAP(v3, @"RemoveToken"),
			 @"SupportApplicationVersion"		: MAP(v3, @"SupportApplicationVersion"),
			 @"UnblockActivation"				: MAP(v3, @"UnblockActivation"),
			 @"UnsupportApplicationVersion"		: MAP(v3, @"UnsupportApplicationVersion"),
			 @"ValidateToken"					: MAP(v3, @"ValidateToken"),
			 @"VerifyECDSASignature"			: MAP(v3, @"VerifyECDSASignature"),
			 @"VerifyOfflineSignature"			: MAP(v3, @"VerifyOfflineSignature"),
			 @"VerifySignature"					: MAP(v3, @"_v3/VerifySignature"),	// Default signature validation (without specified version)
			 @"VerifySignature_ForceVer"		: MAP(v3, @"_v3/VerifySignature_ForceVer"),	// The same template, but with additional "forcedSignatureVersion" param
			 };
}

+ (NSDictionary<NSString*, SoapHelperMapping*>*) mappingForV0_23
{
	NSString * v3 = @"http://getlime.io/security/powerauth/v3";
	return @{
			 @"BlockActivation" 				: MAP(v3, @"BlockActivation"),
			 @"CommitActivation" 				: MAP(v3, @"CommitActivation"),
			 @"CreateApplication" 				: MAP(v3, @"CreateApplication"),
			 @"CreateApplicationVersion" 		: MAP(v3, @"CreateApplicationVersion"),
			 @"CreateNonPersonalizedOfflineSignaturePayload": MAP(v3, @"CreateNonPersonalizedOfflineSignaturePayload"),
			 @"CreatePersonalizedOfflineSignaturePayload"	: MAP(v3, @"CreatePersonalizedOfflineSignaturePayload"),
			 @"CreateToken"						: MAP(v3, @"_v3/CreateToken"),
			 @"GetActivationStatus"				: MAP(v3, @"GetActivationStatus"),
			 @"GetApplicationDetail"			: MAP(v3, @"GetApplicationDetail"),
			 @"GetApplicationList"				: MAP(v3, @"GetApplicationList"),
			 @"GetSystemStatus"					: MAP(v3, @"GetSystemStatus"),
			 @"InitActivation"					: MAP(v3, @"InitActivation"),
			 @"RemoveActivation"				: MAP(v3, @"RemoveActivation"),
			 @"RemoveToken"						: MAP(v3, @"RemoveToken"),
			 @"SupportApplicationVersion"		: MAP(v3, @"SupportApplicationVersion"),
			 @"UnblockActivation"				: MAP(v3, @"UnblockActivation"),
			 @"UnsupportApplicationVersion"		: MAP(v3, @"UnsupportApplicationVersion"),
			 @"ValidateToken"					: MAP(v3, @"ValidateToken"),
			 @"VerifyECDSASignature"			: MAP(v3, @"VerifyECDSASignature"),
			 @"VerifyOfflineSignature"			: MAP(v3, @"VerifyOfflineSignature"),
			 @"VerifySignature"					: MAP(v3, @"_v31/VerifySignature"),	// Default signature validation, now contains explicit protocol version.
			 @"VerifySignature_ForceVer"		: MAP(v3, @"_v31/VerifySignature_ForceVer"),	// The same template, but with additional "forcedSignatureVersion" param
			 };
}

+ (NSDictionary<NSString*, SoapHelperMapping*>*) mappingForV0_23_2
{
	NSString * v3 = @"http://getlime.io/security/powerauth/v3";
	return @{
			 @"BlockActivation" 				: MAP(v3, @"BlockActivation"),
			 @"CommitActivation" 				: MAP(v3, @"CommitActivation"),
			 @"CreateApplication" 				: MAP(v3, @"CreateApplication"),
			 @"CreateApplicationVersion" 		: MAP(v3, @"CreateApplicationVersion"),
			 @"CreateNonPersonalizedOfflineSignaturePayload": MAP(v3, @"CreateNonPersonalizedOfflineSignaturePayload"),
			 @"CreatePersonalizedOfflineSignaturePayload"	: MAP(v3, @"CreatePersonalizedOfflineSignaturePayload"),
			 @"CreateToken"						: MAP(v3, @"_v3/CreateToken"),
			 @"GetActivationStatus"				: MAP(v3, @"GetActivationStatus"),
			 @"GetApplicationDetail"			: MAP(v3, @"GetApplicationDetail"),
			 @"GetApplicationList"				: MAP(v3, @"GetApplicationList"),
			 @"GetSystemStatus"					: MAP(v3, @"GetSystemStatus"),
			 @"InitActivation"					: MAP(v3, @"InitActivation"),
			 @"RemoveActivation"				: MAP(v3, @"RemoveActivation_Revoke"),
			 @"RemoveToken"						: MAP(v3, @"RemoveToken"),
			 @"SupportApplicationVersion"		: MAP(v3, @"SupportApplicationVersion"),
			 @"UnblockActivation"				: MAP(v3, @"UnblockActivation"),
			 @"UnsupportApplicationVersion"		: MAP(v3, @"UnsupportApplicationVersion"),
			 @"ValidateToken"					: MAP(v3, @"ValidateToken"),
			 @"VerifyECDSASignature"			: MAP(v3, @"VerifyECDSASignature"),
			 @"VerifyOfflineSignature"			: MAP(v3, @"VerifyOfflineSignature"),
			 @"VerifySignature"					: MAP(v3, @"_v31/VerifySignature"),	// Default signature validation, now contains explicit protocol version.
			 @"VerifySignature_ForceVer"		: MAP(v3, @"_v31/VerifySignature_ForceVer"),	// The same template, but with additional "forcedSignatureVersion" param
			 };
}

+ (NSDictionary<NSString*, SoapHelperMapping*>*) mappingForV0_24
{
	NSString * v3 = @"http://getlime.io/security/powerauth/v3";
	return @{
			 @"BlockActivation" 				: MAP(v3, @"BlockActivation"),
			 @"CommitActivation" 				: MAP(v3, @"CommitActivation"),
			 @"CreateApplication" 				: MAP(v3, @"CreateApplication"),
			 @"CreateApplicationVersion" 		: MAP(v3, @"CreateApplicationVersion"),
			 @"CreateNonPersonalizedOfflineSignaturePayload": MAP(v3, @"CreateNonPersonalizedOfflineSignaturePayload"),
			 @"CreatePersonalizedOfflineSignaturePayload"	: MAP(v3, @"CreatePersonalizedOfflineSignaturePayload"),
			 @"CreateToken"						: MAP(v3, @"_v3/CreateToken"),
			 @"GetActivationStatus"				: MAP(v3, @"GetActivationStatus"),
			 @"GetApplicationDetail"			: MAP(v3, @"GetApplicationDetail"),
			 @"GetApplicationList"				: MAP(v3, @"GetApplicationList"),
			 @"GetSystemStatus"					: MAP(v3, @"GetSystemStatus"),
			 @"InitActivation"					: MAP(v3, @"InitActivation"),
			 @"RemoveActivation"				: MAP(v3, @"RemoveActivation_Revoke"),
			 @"RemoveToken"						: MAP(v3, @"RemoveToken"),
			 @"SupportApplicationVersion"		: MAP(v3, @"SupportApplicationVersion"),
			 @"UnblockActivation"				: MAP(v3, @"UnblockActivation"),
			 @"UnsupportApplicationVersion"		: MAP(v3, @"UnsupportApplicationVersion"),
			 @"ValidateToken"					: MAP(v3, @"ValidateToken"),
			 @"VerifyECDSASignature"			: MAP(v3, @"VerifyECDSASignature"),
			 @"VerifyOfflineSignature"			: MAP(v3, @"VerifyOfflineSignature"),
			 @"VerifySignature"					: MAP(v3, @"_v31/VerifySignature"),	// Default signature validation, now contains explicit protocol version.
			 @"VerifySignature_ForceVer"		: MAP(v3, @"_v31/VerifySignature_ForceVer"),	// The same template, but with additional "forcedSignatureVersion" param
			 };
}
#undef MAP

@end


@implementation SoapHelperMapping

+ (id) map:(NSArray *)mapArray
{
	SoapHelperMapping * obj = [[SoapHelperMapping alloc] init];
	if (obj) {
		obj->_xmlns = mapArray[0];
		obj->_envelopePath = mapArray[1];
	}
	return obj;
}

@end
