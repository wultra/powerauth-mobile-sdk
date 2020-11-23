/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PowerAuthSDK.h"
#import "PA2PrivateCryptoHelper.h"
#import "PA2Keychain.h"

#if defined(PA2_WATCH_SUPPORT)
#import "PA2WCSessionDataHandler.h"
#endif

@class PA2PrivateEncryptorFactory;

// Exposing several private interfaces
@interface PowerAuthSDK (Private)

/**
 Contains instance identifier
 */
@property (nonatomic, strong, readonly) NSString * privateInstanceId;

/**
 Returns key required for unlok the possesion factor.
 */
- (NSData*) deviceRelatedKey;

/**
 Low level signature calculation. Unlike the high level interface, this method doesn't check
 the protocol upgrade flag. This is useful for situations, where the flag is validated elsewhere, or
 when the request can be signed during the pending protocol upgrade.
 */
- (PA2HTTPRequestDataSignature*) signHttpRequestData:(PA2HTTPRequestData*)requestData
									  authentication:(PowerAuthAuthentication*)authentication
											   error:(NSError**)error;

@end

// Declaration for PA2PrivateCryptoHelper
@interface PowerAuthSDK (CryptoHelper) <PA2PrivateCryptoHelper>
@end

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
// Declaration required by watchSDK integration (see PowerAuthSDK+WatchSupport.m)
@interface PowerAuthSDK (WatchSupportPrivate) <PA2WCSessionDataHandler>
@end
// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

// Reveal private init in PA2ActivationRecoveryData object
@interface PA2ActivationRecoveryData (Private)
- (instancetype) initWithRecoveryData:(PA2RecoveryData*)recoveryData;
@end

// Reveal private readonly property that helps distinguish between "current" or "any set" biometric access.
@interface PA2KeychainConfiguration (BiometricAccess)
@property (nonatomic, readonly) PA2KeychainItemAccess biometricItemAccess;
@end
