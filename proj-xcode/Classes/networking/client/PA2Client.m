/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import "PA2Client.h"
#import "PA2ErrorConstants.h"
#import "PA2Macros.h"

@implementation PA2Client

#pragma mark - Private Methods

/** Take data from error RESTful API response and convert them to NSError.
 
 @param data Data that were returned from the PowerAuth 2.0 Server. This should be a JSON payload in the format described in the API specification.
 @param response NSURLResponse instance associated with the failed request.
 @return NSError instance with the error description. More details are stored in userInfo dictionary under 'PA2ErrorDomain' key.
 */
- (NSError*) processHttpClientErrorForData:(NSData*)data response:(NSURLResponse*)response {
	
	NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse*)response;
	NSError *err = nil;
	NSDictionary *responseDictionary = !data ? nil : [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
	
	PA2ErrorResponse *httpResponseObject;
	httpResponseObject.httpStatusCode = httpResponse.statusCode;
	if (data == nil || err) { // there was no data or data could not be parsed as JSON
		httpResponseObject = [[PA2ErrorResponse alloc] initWithError:nil];
	} else {
		httpResponseObject = [[PA2ErrorResponse alloc] initWithDictionary:responseDictionary];
	}
	NSDictionary * additionalInfo =
  	@{
		PA2ErrorDomain: 				httpResponseObject,
		PA2ErrorInfoKey_AdditionalInfo: responseDictionary ? responseDictionary : @{},
		PA2ErrorInfoKey_ResponseData: 	data ? data : [NSData data]
	 };
	return [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeNetworkError userInfo:additionalInfo];
}

- (NSURL*) urlForRelativePath:(NSString*)urlPath {
	NSString *baseUrl = _baseEndpointUrl;
	if ([baseUrl hasSuffix:@"/"] && baseUrl.length > 1) {
		baseUrl = [baseUrl substringToIndex:baseUrl.length - 1];
	}
	return [NSURL URLWithString:[baseUrl stringByAppendingString:urlPath]];
}

/** Perform a POST request to given resource, with provided data (bytes) and HTTP headers. Returns result in the callback.
 
 @param urlString Absolute resource URL path.
 @param data Data of the POST request body.
 @param headers HTTP headers.
 @param completion A callback that returns either a correct HTTP response, or an error object in case networking issue occurred.
 @return NSURLSessionDataTask associated with the running request.
 */
- (NSURLSessionDataTask*) postToUrl:(NSURL*)url
							   data:(NSData*)data
							headers:(NSDictionary*)headers
						 completion:(void(^)(NSData *data, NSURLResponse *response, NSError *error))completion {
	
	if ([url.absoluteString hasPrefix:@"http://"]) {
		PALog(@"Warning: Using HTTP for communication may create a serious security issue! Use HTTPS in production.");
	}
	
	NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
	configuration.URLCache = nil;
	
	NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
														  delegate:self
													 delegateQueue:[NSOperationQueue mainQueue]];
	
	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
	request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
	[request setTimeoutInterval:_defaultRequestTimeout];
	[request addValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
	[request addValue:@"application/json" forHTTPHeaderField:@"Accept"];
	
	if (headers) {
		for (NSString *header in headers.allKeys) {
			[request addValue:[headers objectForKey:header]	forHTTPHeaderField:header];
		}
	}
	
	[request setHTTPMethod:@"POST"];
	[request setHTTPBody:data];
	
	PALog(@"PA2Client Request");
	PALog(@"- Method: POST");
	PALog(@"- URL: %@", url.absoluteString);
	PALog(@"- Headers: %@", request.allHTTPHeaderFields);
	PALog(@"- Body: %@", data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"empty body");
	NSURLSessionDataTask *postDataTask = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
		PALog(@"PA2Client Response");
		PALog(@"- URL: %@", url.absoluteString);
		PALog(@"- Status code: %ld", (long)((NSHTTPURLResponse*)response).statusCode);
		PALog(@"- Headers: %@", ((NSHTTPURLResponse*)response).allHeaderFields);
		PALog(@"- Body: %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
		PALog(@"- Error: %@", error ? error.localizedDescription : @"no error");
		[[NSOperationQueue mainQueue] addOperationWithBlock: ^{
			completion(data, response, error);
		}];
		[[NSURLCache sharedURLCache] removeCachedResponseForRequest:request];
	}];
	
	[postDataTask resume];
	
	return postDataTask;
}

- (NSData*) embedNetworkObjectIntoRequest:(id<PA2NetworkObject>)object
{
	if (!object) {
		static char s_brackets[] = "{}";
		return [NSData dataWithBytes:s_brackets length:2];
	}
	PA2Request *httpRequestObject = [[PA2Request alloc] init];
	httpRequestObject.requestObject = object;
	return [NSJSONSerialization dataWithJSONObject:[httpRequestObject toDictionary] options:0 error:nil];
}

- (NSURLSessionDataTask*) postToUrl:(NSURL*)absoluteUrl
					  requestObject:(id<PA2NetworkObject>)requestObject
							headers:(NSDictionary*)headers
				responseObjectClass:(Class)responseObjectClass
						   callback:(void(^)(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error))callback {
	
	// Prepare post data if any object was passed
	NSData *postData = [self embedNetworkObjectIntoRequest:requestObject];
	// Post to given URL
	return [self postToUrl:absoluteUrl data:postData headers:headers completion:^(NSData *data, NSURLResponse *response, NSError *error) {
		// No error
		if (!error) {
			if (((NSHTTPURLResponse*)response).statusCode == 200) { // Handle success state
				if (data != nil && data.length > 0 && responseObjectClass != nil) { // Response object is expected, data is available
					NSError *err = nil;
					NSDictionary *responseDictionary = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&err];
					if (err == nil) { // success
						PA2Response *httpResponseObject = [[PA2Response alloc] initWithDictionary:responseDictionary responseObjectType:responseObjectClass];
						if (httpResponseObject.status == PA2RestResponseStatus_OK) {
							callback(PA2RestResponseStatus_OK, httpResponseObject.responseObject, nil);
						} else {
							callback(PA2RestResponseStatus_ERROR, nil, [self processHttpClientErrorForData:data response:response]);
						}
						return;
					} else { // Unable to parse JSON
						callback(PA2RestResponseStatus_ERROR, nil, err);
						return;
					}
				} else { // Response code was OK, but no object can be serialized
					callback(PA2RestResponseStatus_OK, nil, nil);
				}
			} else { // Handle error state
				callback(PA2RestResponseStatus_ERROR, nil, [self processHttpClientErrorForData:data response:response]);
				return;
			}
		} else { // Handle error state, probably a networking issue here
			callback(PA2RestResponseStatus_ERROR, nil, error);
			return;
		}
	}];
}

#pragma mark - High-level Methods

- (NSURLSessionDataTask*) createActivation:(PA2CreateActivationRequest*)request
								  callback:(void(^)(PA2RestResponseStatus status, PA2CreateActivationResponse *response, NSError *error))callback {
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/activation/create"];
	return [self postToUrl:fullUrl requestObject:request headers:nil responseObjectClass:[PA2CreateActivationResponse class] callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, (PA2CreateActivationResponse*)response, error);
	}];
}

- (NSURLSessionDataTask*) getActivationStatus:(PA2ActivationStatusRequest*)request
									 callback:(void(^)(PA2RestResponseStatus status, PA2ActivationStatusResponse *response, NSError *error))callback {
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/activation/status"];
	return [self postToUrl:fullUrl requestObject:request headers:nil responseObjectClass:[PA2ActivationStatusResponse class] callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, (PA2ActivationStatusResponse*)response, error);
	}];
}

- (NSURLSessionDataTask*) removeActivation:(PA2AuthorizationHttpHeader*)signatureHeader
								  callback:(void(^)(PA2RestResponseStatus status, NSError *error))callback {
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/activation/remove"];
	NSDictionary *headers = @{ signatureHeader.key : signatureHeader.value };
	return [self postToUrl:fullUrl requestObject:nil headers:headers responseObjectClass:nil callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, error);
	}];
}

- (NSURLSessionDataTask*) vaultUnlock:(PA2AuthorizationHttpHeader*)signatureHeader
							 callback:(void(^)(PA2RestResponseStatus status, PA2VaultUnlockResponse *response, NSError *error))callback {
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/vault/unlock"];
	NSDictionary *headers = @{ signatureHeader.key : signatureHeader.value };
	return [self postToUrl:fullUrl requestObject:nil headers:headers responseObjectClass:[PA2VaultUnlockResponse class] callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, (PA2VaultUnlockResponse*)response, error);
	}];
}


- (NSURLSessionDataTask*) createToken:(PA2AuthorizationHttpHeader*)signatureHeader
						encryptedData:(PA2EncryptedRequest *)encryptedData
							 callback:(void(^)(PA2RestResponseStatus status, PA2EncryptedResponse * response, NSError * error))callback
{
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/token/create"];
	NSDictionary *headers = @{ signatureHeader.key : signatureHeader.value };
	return [self postToUrl:fullUrl requestObject:encryptedData headers:headers responseObjectClass:[PA2EncryptedResponse class] callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, (PA2EncryptedResponse*)response, error);
	}];
}

- (NSURLSessionDataTask*) removeToken:(PA2RemoveTokenRequest*)request
					  signatureHeader:(PA2AuthorizationHttpHeader*)signatureHeader
							 callback:(void(^)(PA2RestResponseStatus status, NSError * error))callback
{
	NSURL *fullUrl = [self urlForRelativePath:@"/pa/token/remove"];
	NSDictionary *headers = @{ signatureHeader.key : signatureHeader.value };
	return [self postToUrl:fullUrl requestObject:request headers:headers responseObjectClass:[PA2EncryptedResponse class] callback:^(PA2RestResponseStatus status, id<PA2NetworkObject> response, NSError *error) {
		callback(status, error);
	}];
}

#pragma mark - NSURLSessionDelegate methods

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
	if (self.sslValidationStrategy) {
		[self.sslValidationStrategy validateSslForSession:session challenge:challenge completionHandler:completionHandler];
	} else {
		completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
	}
}

@end
