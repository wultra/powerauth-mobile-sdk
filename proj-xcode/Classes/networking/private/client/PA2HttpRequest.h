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

#import "PA2Codable.h"
#import "PA2PrivateCryptoHelper.h"
#import "PA2RestApiEndpoint.h"
#import "PowerAuthAuthentication.h"

/**
 The `PA2HttpRequest` object helps with HTTP request construction and with
 the response processing. The object itself doesn't perform any networking
 and is solely used by the `PA2HttpClient` class.
 */
@interface PA2HttpRequest: NSObject

/**
 Initializes object with endpoint, request object (which is actual payload)
 and with an optional authentication credentials.
 */
- (instancetype) initWithEndpoint:(PA2RestApiEndpoint*)endpoint
					requestObject:(id<PA2Encodable>)requestObject
				   authentication:(PowerAuthAuthentication*)authentication;

/// Contains endpoint object, provided in the object's initialization.
@property (nonatomic, strong, readonly) PA2RestApiEndpoint * endpoint;
/// Contains a request object, provided in the object's initialization.
@property (nonatomic, strong, readonly) id<PA2Encodable> requestObject;
/// Contains copy of authentication object, provided in the object's initialization.
@property (nonatomic, strong, readonly) PowerAuthAuthentication * authentication;

/**
 Builds a mutable URL request from data, provided in the initialization.
 */
- (NSMutableURLRequest*) buildRequestWithHelper:(id<PA2PrivateCryptoHelper>)helper
										baseUrl:(NSString*)baseUrl
										  error:(NSError**)error;
/**
 Builds a response from response data & response object.
 */
- (id<PA2Decodable>) buildResponseObjectFrom:(NSData*)responseData
								httpResponse:(NSHTTPURLResponse*)httpResponse
									   error:(NSError**)error;

@end


