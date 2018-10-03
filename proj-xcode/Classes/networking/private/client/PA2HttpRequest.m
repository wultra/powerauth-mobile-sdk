/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2HttpRequest.h"
#import "PA2ObjectSerialization.h"
#import "PA2ECIESEncryptor.h"
#import "PA2PrivateMacros.h"
#import "PA2EncryptedRequest.h"
#import "PA2ErrorResponse+Decodable.h"
#import "PA2AuthorizationHttpHeader.h"

@implementation PA2HttpRequest
{
	PA2ECIESEncryptor * _encryptor;
}

- (instancetype) initWithEndpoint:(PA2RestApiEndpoint*)endpoint
					requestObject:(id<PA2Encodable>)requestObject
				   authentication:(PowerAuthAuthentication*)authentication
{
	self = [super init];
	if (self) {
		_endpoint = endpoint;
		_requestObject = requestObject;
		_authentication = [authentication copy];
	}
	return self;
}


#pragma mark - Request -

- (NSMutableURLRequest*) buildRequestWithHelper:(id<PA2PrivateCryptoHelper>)helper
										baseUrl:(NSString*)baseUrl
										  error:(NSError**)error
{
	// Sanity checks.
	BOOL needsSignature = _endpoint.authUriId != nil && _authentication != nil;
	BOOL needsEncryption = _endpoint.encryptor != PA2EncryptorId_None;

	// Check whether the request object has expected type.
	if (_endpoint.requestClass && ![_requestObject isKindOfClass:_endpoint.requestClass]) {
		if (error) *error = PA2MakeError(PA2ErrorCodeNetworkError, @"Unexpected type of request object.");
		return nil;
	}
	// The crypto helper is in fact PowerAuthSDK instance, but PA2HttpClient
	// keeps just a weak reference, to break possible retain loop between both objects.
	// So, we need to check whether the instance is still valid and available for
	// the cryptographic operations.
	if ((needsSignature || needsEncryption) && helper == nil) {
		if (error) *error = PA2MakeError(PA2ErrorCodeNetworkError, @"PowerAuthSDK instance is no longer valid.");
		return nil;
	}
	
	// Build full URL & request object
	NSURL * url = [NSURL URLWithString:[baseUrl stringByAppendingString:_endpoint.relativePath]];
	NSMutableURLRequest * request = [[NSMutableURLRequest alloc] initWithURL:url];
	
	// Now prepare body data.
	NSData * requestData;
	// Encrypt request if the endpoint has specified.
	if (!needsEncryption) {
		// Simple request, without data encryption
		_encryptor = nil;
		requestData = [PA2ObjectSerialization serializeRequestObject:_requestObject];
	} else {
		// Acquire encryptor from the helper, and keep it locally.
		// We will use it later, for the response decryption.
		_encryptor = [helper encryptorWithId:_endpoint.encryptor];
		// Encrypt object
		requestData = [PA2ObjectSerialization encryptObject:_requestObject
												  encryptor:_encryptor
													  error:error];
		if (!requestData) {
			return nil;
		}
		// Set encryption HTTP headers, only if this doesn't collide with the signature.
		// We don't sent the encryption header together with the signature header. The reason
		// for that is fact, that signature header already contains values required for
		// decryption on the server.
		if (!needsSignature) {
			PA2ECIESMetaData * md = _encryptor.associatedMetaData;
			[request addValue:md.httpHeaderValue forHTTPHeaderField:md.httpHeaderKey];
		}
	}
	
	// Sign data if requested
	if (needsSignature) {
		PA2AuthorizationHttpHeader * authHeader = [helper authorizationHeaderForData:requestData
																			endpoint:_endpoint
																	  authentication:_authentication
																			   error:error];
		if (!authHeader) {
			return nil;
		}
		// Set authorization headers to the request.
		[request addValue:authHeader.value forHTTPHeaderField:authHeader.key];
	}
	
	// Setup other headers
	[request addValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
	[request addValue:@"application/json" forHTTPHeaderField:@"Accept"];
	return request;
}


#pragma mark - Response -

- (id<PA2Decodable>) buildResponseObjectFrom:(NSData*)responseData
								httpResponse:(NSHTTPURLResponse*)httpResponse
									   error:(NSError**)error
{
	id<PA2Decodable> object;
	NSError * localError = nil;
	if (httpResponse.statusCode == 200) {
		// 200 response, try to build an object from response data.
		object = [self buildObjectFrom:responseData httpResponse:httpResponse error:&localError];
	} else {
		// Non 200 status code always leads to an error.
		localError = [self buildErrorForData:responseData httpResponse:httpResponse];
	}
	if (localError) {
		// Report error & always return nil.
		if (error) *error = localError;
		return nil;
	}
	return object;
}

// Private methods

/**
 Private function builds a response object from available data & HTTP response.
 If response class is not specified, then return nil. The function also
 */
- (id<PA2Decodable>) buildObjectFrom:(NSData*)responseData
						httpResponse:(NSHTTPURLResponse*)httpResponse
							   error:(NSError**)error
{
	NSError * localError = nil;
	
	// Prepare data for object deserialization
	NSData * objectData;
	BOOL unwrapResponse;
	if (_encryptor) {
		// Encrypted response. The expected object is never wrapped in PA2Response.
		unwrapResponse = NO;
		objectData = [PA2ObjectSerialization decryptData:responseData decryptor:_encryptor
												   error:&localError];
		if (localError) {
			if (error) *error = localError;
			return nil;
		}
	} else {
		// Regular response. It's always wrapped in PA2Response object
		unwrapResponse = YES;
		objectData = responseData;
	}
	
	// So far so good, we can continue with an object deserialization.
	id<PA2Decodable> object = nil;
	if (unwrapResponse) {
		// It's expected that response object is wrapped in PA2Response
		PA2Response * ro = [PA2ObjectSerialization deserializeResponseObject:objectData forClass:_endpoint.responseClass
																	   error:&localError];
		if (ro) {
			if (ro.status == PA2RestResponseStatus_OK) {
				// Success. Note that responseObject may be nil, if response class is not specified.
				object = ro.responseObject;
			} else {
				// Status is ERROR, we need to build NSError with an associated data.
				localError = [self buildErrorForData:objectData httpResponse:httpResponse];
			}
		}
	} else {
		// Response object is not wrapped in PA2Response.
		if (_endpoint.responseClass) {
			// If class is specified, then try to deserialize object. Unlike the request deserialization,
			// the "deserializeObject:..." method expects that the class is specified.
			object = [PA2ObjectSerialization deserializeObject:objectData forClass:_endpoint.responseClass
														 error:&localError];
		} else {
			// No action needed. If class is not specified, then "object" variable can be nil.
		}
	}
	if (localError) {
		if (error) *error = localError;
		return nil;
	}
	return object;
}

/**
 Private function builds NSError object from available data & HTTP response.
 The returned error has "domain" equal to `PA2ErrorDomain` and contains additional
 information bundled in the "userInfo" dictionary.
 */
- (NSError*) buildErrorForData:(NSData*)data
				  httpResponse:(NSHTTPURLResponse*)httpResponse
{
	NSError * localError = nil;
	// Try to deserialize JSON
	id JSONData = [NSJSONSerialization JSONObjectWithData:data options:0 error:&localError];
	NSDictionary * responseDictionary = data ? nil : PA2ObjectAs(JSONData, NSDictionary);
	// Create PA2ErrorResponse object.
	// If there was an error with JSON decoding, then use nil for object constuction.
	PA2ErrorResponse * httpResponseObject = [[PA2ErrorResponse alloc] initWithDictionary:localError ? nil : responseDictionary];
	// Keep status code in response object
	httpResponseObject.httpStatusCode = httpResponse.statusCode;
	
	NSDictionary * additionalInfo =
	@{
	  	PA2ErrorDomain: 				httpResponseObject,
	  	PA2ErrorInfoKey_AdditionalInfo: responseDictionary ? responseDictionary : @{},
	  	PA2ErrorInfoKey_ResponseData: 	data ? data : [NSData data]
	};
	return [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeNetworkError userInfo:additionalInfo];
}

@end
