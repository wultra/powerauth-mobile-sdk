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

#import <Foundation/Foundation.h>

/** Class that represents the Authorization HTTP header with the PowerAuth 2.0 signature
 */
@interface PA2AuthorizationHttpHeader : NSObject

/** Property representing PowerAuth 2.0 HTTP Authorization Header, value "X-PowerAuth-Authorization".
 */
@property (nonatomic, strong, readonly, nonnull) NSString *key;

/** Computed value of the PowerAuth 2.0 HTTP Authorization Header, to be used in HTTP requests "as is".
 */
@property (nonatomic, strong, readonly, nullable) NSString *value;

/** Initialize a new instance with given header value.
 
 @param value Value of the PowerAuth 2.0 HTTP Authorization Header.
 @return Instance of the PowerAuth 2.0 HTTP Authorization Header object.
 */
- (nullable instancetype)initWithValue:(nullable NSString*)value;

@end
