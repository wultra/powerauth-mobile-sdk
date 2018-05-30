/**
 * Copyright 2018 Lime - HighTech Solutions s.r.o.
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

#ifdef __OBJC__
#import <WatchKit/WatchKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

//! Project version number for PowerAuth2ForWatch.
FOUNDATION_EXPORT double PowerAuth2ForWatchVersionNumber;

//! Project version string for PowerAuth2ForWatch.
FOUNDATION_EXPORT const unsigned char PowerAuth2ForWatchVersionString[];

// Import all public headers...
#import "PA2Macros.h"
#import "PA2Log.h"
#import "PA2ErrorConstants.h"
#import "PA2SessionStatusProvider.h"
#import "PA2KeychainConfiguration.h"
#import "PA2Keychain.h"
#import "PowerAuthAuthentication.h"
#import "PowerAuthConfiguration.h"
#import "PowerAuthToken.h"
#import "PA2AuthorizationHttpHeader.h"
#import "PA2ExtensionLibrary.h"
#import "PA2WCSessionManager.h"
#import "PowerAuthWatchSDK.h"
