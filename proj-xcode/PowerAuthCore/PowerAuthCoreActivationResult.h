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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

/// The `PowerAuthCoreActivationResult` object represents successful result from
/// the activation process.
@interface PowerAuthCoreActivationResult : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Decimalized fingerprint calculated from device and server public keys.
@property (nonatomic, strong, readonly, nonnull) NSString * activationFingerprint;

/// Custom attributes received from the server. The value may be nil in case that there
/// are no custom attributes available.
@property (nonatomic, strong, readonly, nullable) NSDictionary<NSString*, NSObject*>* customAttributes;

/// Information about user's identity. The value is optional and depending on whether the server
/// implementation provide such information in the time of activation.
@property (nonatomic, strong, readonly, nullable) NSDictionary<NSString*, NSObject*>* userInfo;

@end
