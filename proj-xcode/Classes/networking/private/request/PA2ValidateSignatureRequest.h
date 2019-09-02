/**
 * Copyright 2019 Wultra s.r.o.
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

/**
 The request object that wraps arbitrary data send to signature validation endpoint.
 */
@interface PA2ValidateSignatureRequest : NSObject<PA2Encodable>

/**
 Returns request's instance initialized with provided dictionary.
 The dictionary will be then serialized to the JSON payload.
 */
+ (instancetype) requestWithDictionary:(NSDictionary<NSString*, NSObject*>*)dictionary;

/**
 Returns request's instance initialized with the provided message.
 The { "reason" : reason } dictionary will be then serialized to the JSON payload.
 */
+ (instancetype) requestWithReason:(NSString *)reason;

@end
