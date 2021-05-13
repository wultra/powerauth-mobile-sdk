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

#import <Foundation/Foundation.h>

//! Project version number for PowerAuth2.
FOUNDATION_EXPORT double PowerAuth2VersionNumber;

//! Project version string for PowerAuth2.
FOUNDATION_EXPORT const unsigned char PowerAuth2VersionString[];

#import <PowerAuth2/PowerAuthSDK.h>
#import <PowerAuth2/PowerAuthActivationCode.h>
#import <PowerAuth2/PowerAuthErrorConstants.h>
#import <PowerAuth2/PowerAuthKeychain.h>

#import <PowerAuth2/PowerAuthRestApiError.h>
#import <PowerAuth2/PowerAuthRestApiErrorResponse.h>
#import <PowerAuth2/PowerAuthClientSslNoValidationStrategy.h>
#import <PowerAuth2/PowerAuthBasicHttpAuthenticationRequestInterceptor.h>
#import <PowerAuth2/PowerAuthCustomHeaderRequestInterceptor.h>

#import <PowerAuth2/PowerAuthLog.h>
#import <PowerAuth2/PowerAuthSystem.h>

#import <PowerAuth2/PowerAuthWCSessionManager.h>
