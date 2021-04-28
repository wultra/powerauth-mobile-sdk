/*
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

#import <PowerAuth2/PowerAuthActivationRecoveryData.h>

/**
 The PowerAuthActivationResult object represents successfull result from the activation
 process.
 */
@interface PowerAuthActivationResult : NSObject
/**
 Decimalized fingerprint calculated from device's public key.
 */
@property (nonatomic, strong, nonnull) NSString * activationFingerprint;
/**
 If supported and enabled on the server, then the object contains "Recovery Code" and PUK,
 created for this particular activation. Your application should display that values to the user
 and forget the values immediately. You should NEVER store values from the object persistently on the device.
 */
@property (nonatomic, strong, nullable) PowerAuthActivationRecoveryData * activationRecovery;
/**
 Custom attributes received from the server. The value may be nil in case that there
 are no custom attributes available.
 */
@property (nonatomic, strong, nullable) NSDictionary<NSString*, NSObject*>* customAttributes;

@end
