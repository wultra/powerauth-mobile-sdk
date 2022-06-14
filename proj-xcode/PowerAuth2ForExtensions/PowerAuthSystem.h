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

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

@interface PowerAuthSystem : NSObject

/**
 Detects if the PowerAuth SDK is compiled with debug features.
 
 @return YES if library uses debug features, NO otherwise.
 */
+ (BOOL) isInDebug;

/**
 Returns string representing the current device's platform (e.g. "ios", "tvos", etc.)
 */
+ (nonnull NSString*) platform;

/**
 Returns more detailed information about the device (e.g. "iPhone12,3")
 */
+ (nonnull NSString*) deviceInfo;

/**
 Returns default user agent for internal networking or nil in case that
 user agent string cannot be provided.
 
 The default string is typically composed as: "%MainBundleVersion% %PowerAuthFrameworkVersion% (%OsVersion%, %DeviceInfo%)".
 For example: "PowerAuth2TestsHostApp-ios/1.0 PowerAuth2/1.6.3 (iOS 15.2, iPhone12.3)".
 */
+ (nullable NSString*) defaultUserAgent;

@end
