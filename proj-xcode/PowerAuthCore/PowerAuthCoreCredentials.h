/*
 * Copyright 2025 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreData.h>

@interface PowerAuthCoreCredentials : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Create credentials with possession factor only.
+ (nonnull PowerAuthCoreCredentials*) possession;

/// Create credentials with possession and knowledge factor.
+ (nullable PowerAuthCoreCredentials*) knowledge:(nonnull PowerAuthCorePassword*)password;

/// Create credentials with possession and biometry factor
+ (nullable PowerAuthCoreCredentials*) biometry:(nonnull PowerAuthCoreData*)biometryKek;

@end
