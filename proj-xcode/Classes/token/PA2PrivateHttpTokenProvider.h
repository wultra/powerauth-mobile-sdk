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

#import "PA2PrivateRemoteTokenProvider.h"

@class PA2HttpClient;

/**
 The `PA2PrivateHttpTokenProvider` class implements getting tokens from remote HTTP server.
 */
@interface PA2PrivateHttpTokenProvider : NSObject<PA2PrivateRemoteTokenProvider>

/**
 A reference to PA2HttpClient, owned by the PowerAuthSDK.
 */
@property (nonatomic, strong, readonly) PA2HttpClient * httpClient;

/**
 Initializes remote token provider with HTTP client, providing
 communication with the server.
 */
- (id) initWithHttpClient:(PA2HttpClient*)httpClient;

@end
