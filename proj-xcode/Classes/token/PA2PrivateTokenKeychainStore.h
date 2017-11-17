/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PowerAuthToken.h"

@class PowerAuthSDK, PA2Keychain;

/**
 The PA2PrivateTokenKeychainStore object implements token store which
 stores tokens into the IOS keychain. Each created token has its own
 database entry, with using token's name as unique identifier.
 
 The class also implements fetching token from the PA2 server.
 */
@interface PA2PrivateTokenKeychainStore : NSObject<PowerAuthTokenStore>

/**
 Initializes keychain token store with parent SDK object and keychain.
 Internally, weak reference is used for SDK and strong for the keychain.
 */
- (id) initWithSdk:(PowerAuthSDK*)sdk keychain:(PA2Keychain*)keychain;

@end
