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

#import "PA2Codable.h"

@class PA2ECIESCryptogram;

@interface PA2EncryptedResponse: NSObject<PA2Decodable>

@property (nonatomic, strong) NSString * encryptedData;
@property (nonatomic, strong) NSString * mac;

- (PA2ECIESCryptogram*) cryptogram;

@end
