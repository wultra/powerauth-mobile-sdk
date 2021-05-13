/**
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthClientConfiguration.h>

/**
 The `PowerAuthCustomHeaderRequestInterceptor` class implements `PowerAuthHttpRequestInterceptor` interface and allows
 you to set an arbitrary HTTP header and value to the requests created in PowerAuth SDK.
 */
@interface PowerAuthCustomHeaderRequestInterceptor : NSObject<PowerAuthHttpRequestInterceptor>

/**
 Initializes object with a custom HTTP request header and value.

 @param headerKey String with HTTP header's key
 @param value String with corresponding header's value.
 @return Initialized instance of interceptor,
 */
- (nonnull instancetype) initWithHeaderKey:(nonnull NSString*)headerKey value:(nonnull NSString*)value;

/**
 Contains HTTP header's key provided in object's initialization.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * headerKey;

/**
 Contains HTTP header's value provided in object's initialization.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * headerValue;

@end

