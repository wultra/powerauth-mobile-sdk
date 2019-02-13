/**
 * Copyright 2016 Wultra s.r.o.
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

#import "PA2EncryptedResponse.h"

/**
 Response for '/pa/activation/create' endpoint.
 */
@interface PA2CreateActivationResponse : NSObject <PA2Decodable>

/**
 Property contains encrypted, private data, returned from the PowerAuth server.
 The encrypted `PA2CreateActivationResponseData` object is expected.
 */
@property (nonatomic, strong) PA2EncryptedResponse * activationData;

/**
 Custom attributes received from the server. The value may be nil.
 */
@property (nonatomic, strong) NSDictionary<NSString*, NSObject*>* customAttributes;

@end
