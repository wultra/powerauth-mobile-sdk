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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthToken.h>

#import "PA2PrivateTokenData.h"

/**
 The `PowerAuthPrivateTokenStore` protocol extends `PowerAuthTokenStore`
 with private functions.
 */
@protocol PowerAuthPrivateTokenStore <PowerAuthTokenStore>
@required
/**
 Determine whether token can be still used for 
 */
- (BOOL) canGenerateHeaderForToken:(nonnull PowerAuthToken*)token;

/**
 Store token data.
 */
- (void) storeTokenData:(nonnull PA2PrivateTokenData*)tokenData;

/**
 Remove task that crate a new token from the list of pending tasks.
 The task is identified by the token name.
 */
- (void) removeCreateTokenTask:(nonnull NSString*)tokenName;

/**
 Cancel all pending tasks.
 */
- (void) cancelAllTasks;

@end


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
- (nonnull id) initWithStore:(nonnull id<PowerAuthPrivateTokenStore>)store
                        data:(nonnull PA2PrivateTokenData*)data;

@end

