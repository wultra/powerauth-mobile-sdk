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

#import <UIKit/UIKit.h>

//! Project version number for PowerAuth2.
FOUNDATION_EXPORT double PowerAuth2VersionNumber;

//! Project version string for PowerAuth2.
FOUNDATION_EXPORT const unsigned char PowerAuth2VersionString[];

#import "PowerAuthSDK.h"

#import "PA2Client.h"
#import "PA2Macros.h"
#import "PA2System.h"
#import "PA2Keychain.h"

#import "PA2ErrorConstants.h"
#import "PA2PasswordUtil.h"
#import "PA2Password.h"
#import "PA2OtpUtil.h"
#import "PA2ECIESEncryptor.h"

#import "PA2WCSessionManager.h"
