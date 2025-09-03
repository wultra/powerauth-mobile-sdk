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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2/PowerAuthMacros.h>

@class PowerAuthCoreHttpHeader;

/**
 Class representing HTTP header generated in PowerAuth mobile SDK.
 */
@interface PowerAuthHttpHeader : NSObject

/**
 HTTP header's name
 */
@property (nonatomic, strong, readonly, nonnull) NSString *key;

/**
 HTTP header's value
 */
@property (nonatomic, strong, readonly, nonnull) NSString *value;

/// Create header with content from the core header.
/// - Parameter coreHeader: Header returned from PowerAuthCore module.
/// - Returns: New instance of HTTP header created with content from core header.
+ (nullable PowerAuthHttpHeader*) createWithCoreHeader:(nonnull PowerAuthCoreHttpHeader*)coreHeader;

@end

PA2_DEPRECATED_TYPE(2.0.0, PowerAuthAuthorizationHttpHeader, PowerAuthHttpHeader)
