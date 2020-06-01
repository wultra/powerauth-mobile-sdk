/*
 * Copyright 2020 Wultra s.r.o.
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

#import <Foundation/Foundation.h>

//! Project version number for PowerAuthCore.
FOUNDATION_EXPORT double PowerAuthCoreVersionNumber;

//! Project version string for PowerAuthCore.
FOUNDATION_EXPORT const unsigned char PowerAuthCoreVersionString[];

#import "PA2Types.h"
#import "PA2CoreLog.h"
#import "PA2CryptoUtils.h"
#import "PA2ECIESEncryptor.h"
#import "PA2ErrorConstants.h"
#import "PA2Macros.h"
#import "PA2OtpUtil.h"
#import "PA2Password.h"
#import "PA2PlatformCrypto.h"
#import "PA2PrivateMacros.h"
#import "PA2ProtocolUpgradeData.h"
#import "PA2Session.h"
#import "PA2SessionStatusProvider.h"
#import "PA2WeakArray.h"

