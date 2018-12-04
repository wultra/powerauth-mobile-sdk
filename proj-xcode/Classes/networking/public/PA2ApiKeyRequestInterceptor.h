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

#import "PA2HttpRequestInterceptor.h"

/**
 The `PA2ApiKeyRequestInterceptor` class implements `PA2RequestInterceptor` interface and allows
 you set an arbitrary API key and value to the HTTP request. The API key is used for HTTP header's key
 and similarly the value is used as header's value.
 */
@interface PA2ApiKeyRequestInterceptor : NSObject<PA2HttpRequestInterceptor>

/**
 Initializes object with API key and value.

 @param apiKey String with API key
 @param value String with corresponding value for API key.
 @return Initialized instance of interceptor,
 */
- (instancetype) initWithApiKey:(nonnull NSString*)apiKey value:(nonnull NSString*)value;

/**
 Contains API key provided in object's initialization.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * apiKey;

/**
 Contains value provided in object's initialization.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * value;

@end

