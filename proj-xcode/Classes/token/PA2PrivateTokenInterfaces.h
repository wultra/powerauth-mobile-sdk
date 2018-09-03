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

#import "PowerAuthToken.h"
#import "PA2PrivateTokenData.h"

/**
 The category provides a private interface for PowerAuthToken object.
 The header is not available in public library builds (e.g. for CocoaPods)
 */
@interface PowerAuthToken (Private)

/**
 Reference to private data object
 */
@property (nonatomic, readonly, strong, nonnull) PA2PrivateTokenData * privateTokenData;

/**
 Initializes token with parent store and with its private data. The internal
 reference to store object is weak.
 */
- (nonnull id) initWithStore:(nonnull id<PowerAuthTokenStore>)store
						data:(nonnull PA2PrivateTokenData*)data;

@end

