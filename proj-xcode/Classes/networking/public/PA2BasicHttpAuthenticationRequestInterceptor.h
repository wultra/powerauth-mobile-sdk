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

#import "PA2CustomHeaderRequestInterceptor.h"

/**
 The `PA2BasicHttpAuthenticationInterceptor` class implements Basic HTTP Authentication.
 You can construct this object with username and password and assign it to the array of interceptors
 available in `PA2ClientConfiguration` class.
 */
@interface PA2BasicHttpAuthenticationRequestInterceptor : PA2CustomHeaderRequestInterceptor

/**
 Initializes interceptor with username and password, to authorize on the server.

 @param username String with username
 @param password String with password
 @return Initialized instance of interceptor.
 */
- (nonnull instancetype) initWithUsername:(nonnull NSString*)username password:(nonnull NSString*)password;

@end

