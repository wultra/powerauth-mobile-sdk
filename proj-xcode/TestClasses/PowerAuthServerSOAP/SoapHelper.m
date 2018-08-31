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
	NSDictionary * _xmlNamespaceMapping;
}

- (id) initWithBundle:(NSBundle *)bundle
				  url:(NSURL*)url
{
	self = [super init];
	if (self) {
		_bundle = bundle;
		_url = url;
		_cache = [NSMutableDictionary dictionary];
		_xmlNamespaceMapping = @{
			@"soap" : @"http://schemas.xmlsoap.org/soap/envelope/",
			@"pa"   : @"http://getlime.io/security/powerauth"
		 };
		_session = [NSURLSession sharedSession];
	}
	return self;
}

- (id) soapRequest:(NSString*)requestName
			  params:(NSArray*)params
			response:(NSString*)responseNodeName
		   transform:(id (^)(CXMLNode * soapBody, NSDictionary * xmlNamespaceMapping))transformBlock
{
	NSString * envelopeData = [self formatEnvelope:requestName params:params];
	
	if (!envelopeData) {
		@throw [NSException exceptionWithName:@"SoapError" reason:@"Unable to format SOAP envelope." userInfo:nil];
	}
	
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
					CXMLNode * bodyNode = [self lookForSoapBodyNode:document responseNode:responseNodeName error:&error];
					if (!error && bodyNode) {
						// Report SOAP body node
						responseObject = transformBlock(bodyNode, _xmlNamespaceMapping);
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
					 responseNode:(NSString*)responseNode
							error:(NSError**)error
{
	NSError * localError = nil;
	CXMLElement * root = xmlDocument.rootElement;
	CXMLNode * fault = [root nodeForXPath:@"/soap:Envelope/soap:Body/soap:Fault" namespaceMappings:_xmlNamespaceMapping error:&localError];
	if (fault) {
		NSString * faultMessage = [fault nodeForXPath:@"faultstring" namespaceMappings:_xmlNamespaceMapping error:&localError].stringValue;
		if (!faultMessage) {
			faultMessage = @"Unknown failure received from server. XML is valid, but there's no string value for error";
		}
		localError = [NSError errorWithDomain:@"SoapError" code:1 userInfo:@{NSLocalizedDescriptionKey:faultMessage}];
	}
	if (!localError) {
		CXMLNode * responseBody = [[root nodesForXPath:@"/soap:Envelope/soap:Body" namespaceMappings:_xmlNamespaceMapping error:&localError] firstObject];
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
- (NSString*) formatEnvelope:(NSString*)templateName params:(NSArray*)params
{
	// 1) Look for template string
	NSString * templateString = [_cache objectForKey:templateName];
	if (!templateString) {
		// Load XML template from bundle
		NSString * path = [_bundle pathForResource:templateName ofType:@"xml"];
		if (!path) {
			NSLog(@"Requested SOAP template doesn't exist");
			return nil;
		}
		NSData * templateData = [[NSData alloc] initWithContentsOfFile:path];
		templateString = [[NSString alloc] initWithData:templateData encoding:NSUTF8StringEncoding];
		if (!templateData || !templateString) {
			NSLog(@"Can't load data for SOAP template");
			return nil;
		}
		// Store to cache
		[_cache setObject:templateString forKey:templateName];
	}
	// 2) Remplace all $X placeholders with values from params array
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


@end
