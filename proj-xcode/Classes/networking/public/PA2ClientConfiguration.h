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

#import "PA2ClientSslValidationStrategy.h"
#import "PA2HttpRequestInterceptor.h"

/**
 Class that is used to provide default (shared) RESTful API client configuration.
 */
@interface PA2ClientConfiguration : NSObject<NSCopying>

/**
 Property that specifies the default HTTP client request timeout. The default value is 20.0 (seconds).
 */
@property (nonatomic, assign) NSTimeInterval defaultRequestTimeout;

/**
 Property that specifies the SSL validation strategy applied by the client. The default value is the default NSURLSession behavior.
 */
@property (nonatomic, strong, nullable) id<PA2ClientSslValidationStrategy> sslValidationStrategy;

/**
 Property that specifies the list of request interceptors used by the client before the request is executed. The default value is nil.
 */
@property (nonatomic, strong, nullable) NSArray<id<PA2HttpRequestInterceptor>>* requestInterceptors;

/**
 Return the shared in stance of a client configuration object.
 
 @return Shared instance of a client configuration.
 */
+ (nonnull PA2ClientConfiguration*) sharedInstance;

@end
