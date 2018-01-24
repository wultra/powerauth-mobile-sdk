/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PowerAuthConfiguration.h"
#import "PowerAuthToken.h"
#import "PA2SessionStatusProvider.h"
#import "PA2KeychainConfiguration.h"
#import "PA2AuthorizationHttpHeader.h"

@interface PowerAuthWatchSDK : NSObject<PA2SessionStatusProvider>

/**
 Instance of the token store object, which provides interface for generating token based authentication headers.
 The current implementation is keeping acquired tokens in the PA2Keychain under the `PA2KeychainConfiguration.keychainInstanceName_TokenStore` service name.
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthTokenStore> tokenStore;

/**
 Instance of configuration, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthConfiguration * configuration;

/**
 Contains activationId if counterpart session object on iPhone has a valid activation or nil if there's no
 such activation.
 */
@property (nonatomic, strong, nullable, readonly) NSString * activationId;

/**
 A designated initializer.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration*)configuration;

@end

/**
 The StatusSynchronization category provides interface for activation status from iPhone.
 */
@interface PowerAuthWatchSDK (StatusSynchronization)

/**
 Gets activation status update from the paired iPhone. The status transmission is performed with using
 `WCSession.transferUserInfo()` method, so the information will be available once watchOS and IOS decide
 to transmit data and appropriate response.
 
 Method returns YES if send operation has been issued, otherwise NO. You can get the negative return value
 typically when the WCSession is not activated yet.
 */
- (BOOL) updateActivationStatus;

/**
 Gets activation status update from the paired iPhone. The status transmission is performed immediately
 with using `WCSession.sendMessageData(..)` method, so the iPhone has to be reachable in the time of the call.
 
 The completion handler will be called on main thread, with non-nil `activationId` if the session is still active
 on iPhone. The error parameter is non-nil only in case of communication error.
 */
- (void) updateActivationStatusWithCompletion:(void(^ _Nonnull)(NSString * _Nullable activationId, NSError * _Nullable error))completion;

@end
