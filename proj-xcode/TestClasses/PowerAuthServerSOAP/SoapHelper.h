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

#import "CXMLElement.h"
#import "CXMLNode_XPathExtensions.h"

/**
 The |SoapHelper| is a simple class which helps with communication to SOAP endpoints.
 The class is very simple and basically provides only formatting the request envelopes
 and helps with response processing.
 
 Note that the class is part of PowerAuth integration tests, so you should NOT use 
 this code in any production-grade application.
 */
@interface SoapHelper : NSObject

/**
 Contains internal NSURLSession object.
 */
@property (nonatomic, strong, readonly) NSURLSession * session;

/**
 Initializes an instance of SoapHelper object with |bundle| containing the SOAP envelope templates.
 The |url| defines endpoint, where the server listens for messages.
 */
- (id) initWithBundle:(NSBundle*)bundle
				  url:(NSURL*)url;

/**
 Sends synchronous HTTP request to SOAP endpoint. The |reqiestName| and |params| parameters are
 used for the request envelope construction, the |responseNodeName| parameter is the name of
 expected XML node in the SOAP response. The |transformBlock| provides a transformation from
 XML to NSObject representation. 
 
 The method returns NSObject, transformed in the provided |transformBlock| or throws an exception
 when the error occurs during the processing.
 */
- (id) soapRequest:(NSString*)requestName
			params:(NSArray*)params
		  response:(NSString*)responseNodeName
		 transform:(id (^)(CXMLNode * responseObject, NSDictionary * xmlNamespaceMapping))transformBlock;


@end
