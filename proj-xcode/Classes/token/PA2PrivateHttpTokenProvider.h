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

#import "PA2PrivateRemoteTokenProvider.h"

@class PowerAuthSDK;

/**
 The `PA2PrivateHttpTokenProvider` class implements getting tokens from remote HTTP server.
 */
@interface PA2PrivateHttpTokenProvider : NSObject<PA2PrivateRemoteTokenProvider>

/**
 A weak reference to the parent SDK.
 */
@property (nonatomic, weak, readonly) PowerAuthSDK * sdk;

/**
 Initializes remote token provider with parent PowerAuthSDK instance. The weak reference
 to SDK object is used internally.
 */
- (id) initWithSdk:(PowerAuthSDK*)sdk;

@end
