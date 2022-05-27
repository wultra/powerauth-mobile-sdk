/*
 * Copyright 2022 Wultra s.r.o.
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

#if PA2_HAS_LACONTEXT == 1
#import <LocalAuthentication/LocalAuthentication.h>
#endif

/**
 The `PowerAuthKeychainAuthentication` class allows you alter biometric dialog
 displayed when keychain item is protected with biometry.
 */
@interface PowerAuthKeychainAuthentication : NSObject

- (nonnull instancetype) init NS_UNAVAILABLE;

/**
 Contains prompt in case that object was initialized with prompt.
 */
@property (nonatomic, nullable, strong, readonly) NSString * prompt;

/**
 Initialize object with prompt that will be displayed to the user in case of biometric authentication.
 */
- (nonnull instancetype) initWithPrompt:(nonnull NSString*)prompt;

/**
 Contains LAContext in case that object was initialized with local authentication context.
 */
@property (nonatomic, nullable, strong, readonly) LAContext * context API_UNAVAILABLE(watchos, tvos);

/**
 Initialize object with local authentication context that allows you to alter more parameters
 of dialog displayed in case of biometric authentication.
 */
- (nonnull instancetype) initWithContext:(nonnull LAContext*)context API_UNAVAILABLE(watchos, tvos);

@end

