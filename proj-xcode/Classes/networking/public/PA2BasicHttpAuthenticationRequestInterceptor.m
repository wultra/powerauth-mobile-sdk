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

#import "PA2BasicHttpAuthenticationRequestInterceptor.h"

@implementation PA2BasicHttpAuthenticationRequestInterceptor

/**
 Private function calculates Basic HTTP Authorization header's value for given username and password.

 @param username String with user name
 @param password String with password
 @return String with Basic HTTP Authorization header value
 */
static NSString * _Nonnull _BasicHttpHeaderValue(NSString *  _Nonnull username, NSString *  _Nonnull password)
{
	NSData * payload = [[[username stringByAppendingString:@":"] stringByAppendingString:password] dataUsingEncoding:NSUTF8StringEncoding];
	return [@"Basic " stringByAppendingString:[payload base64EncodedStringWithOptions:0]];
}

- (instancetype) initWithUsername:(nonnull NSString*)username password:(nonnull NSString*)password
{
	return [super initWithHeaderKey:@"Authorization" value:_BasicHttpHeaderValue(username, password)];
}

@end
