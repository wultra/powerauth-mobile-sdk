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

#import <PowerAuth2/PowerAuthSDK.h>
#import <PowerAuth2/PowerAuthKeychain.h>

#import "PA2PrivateCryptoHelper.h"
#import "PA2GetActivationStatusTask.h"
#import "PowerAuthActivationStatus+Private.h"
#import "PowerAuthActivationCode+Private.h"
#import "PowerAuthAuthentication+Private.h"

@import PowerAuthCore;

// Exposing several private interfaces
@interface PowerAuthSDK (Private) <PA2GetActivationStatusTaskDelegate>

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
- (PowerAuthCoreHTTPRequestDataSignature*) signHttpRequestData:(PowerAuthCoreHTTPRequestData*)requestData
												authentication:(PowerAuthAuthentication*)authentication
														 error:(NSError**)error;

@end

// Declaration for PA2PrivateCryptoHelper
@interface PowerAuthSDK (CryptoHelper) <PA2PrivateCryptoHelper>
@end

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#import "PA2WCSessionDataHandler.h"
// Declaration required by watchSDK integration (see PowerAuthSDK+WatchSupport.m)
@interface PowerAuthSDK (WatchSupportPrivate) <PA2WCSessionDataHandler>
@end
// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

// Reveal private init in PowerAuthActivationRecoveryData object
@interface PowerAuthActivationRecoveryData (Private)
- (instancetype) initWithRecoveryData:(PowerAuthCoreRecoveryData*)recoveryData;
@end

// Reveal private readonly property that helps distinguish between "current" or "any set" biometric access.
@interface PowerAuthKeychainConfiguration (BiometricAccess)
@property (nonatomic, readonly) PowerAuthKeychainItemAccess biometricItemAccess;
@end

// Reveal private property that helps convert LAContext or prompt into PowerAuthKeychainAuthentication.
@interface PowerAuthAuthentication (KeychainAuth)
@property (nonatomic, strong, readonly) PowerAuthKeychainAuthentication * keychainAuthentication;
@end
