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

/**
 The `PA2ActivationRequestData` object contains private data sent during the activation
 directly to the PowerAuth server. The content of the object cannot be decrypted
 by the intermediate application server.
 */
@interface PA2CreateActivationRequestData : NSObject<PA2Encodable>

@property (nonatomic, strong) NSString * devicePublicKey;
@property (nonatomic, strong) NSString * activationName;
@property (nonatomic, strong) NSString * extras;
@property (nonatomic, strong) NSString * activationOtp;
@property (nonatomic, strong) NSString * platform;
@property (nonatomic, strong) NSString * deviceInfo;

@end
