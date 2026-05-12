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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#ifndef PA2PrivateConstants_Included
#define PA2PrivateConstants_Included

// Error constants

#define PA2Def_PowerAuthErrorDomain                 @"PowerAuthErrorDomain"
#define PA2Def_PowerAuthErrorInfoKey_AdditionalInfo @"PowerAuthErrorInfoKey_AdditionalInfo"
#define PA2Def_PowerAuthErrorInfoKey_ResponseData   @"PowerAuthErrorInfoKey_ResponseData"
#define PA2Def_PowerAuthErrorInfoKey_ResponseData   @"PowerAuthErrorInfoKey_ResponseData"
#define PA2Def_PowerAuthErrorInfoKey_ExtPendingApp  @"PowerAuthErrorInfoKey_ExternalPendingApplication"

// Keychain constants, must keep PA2* naming to maintaing a compatibility with older SDK versions

#define PA2Def_PowerAuthKeychainKey_Possession      @"PA2KeychainKey_Possession"
#define PA2Def_PowerAuthKeychain_Initialized        @"io.getlime.PowerAuthKeychain.Initialized"
#define PA2Def_PowerAuthKeychain_Status             @"io.getlime.PowerAuthKeychain.StatusKeychain"
#define PA2Def_PowerAuthKeychain_Possession         @"io.getlime.PowerAuthKeychain.PossessionKeychain"
#define PA2Def_PowerAuthKeychain_Biometry           @"io.getlime.PowerAuthKeychain.BiometryKeychain"
#define PA2Def_PowerAuthKeychain_TokenStore         @"io.getlime.PowerAuthKeychain.TokenStore"

// Maximum length in bytes reserved for appIdentifier.
#define PADef_PowerAuthSharing_AppIdentifierMaxSize 127

// Maximum length in bytes reserved for sharedMemoryIdentifier.
#define PADef_PowerAuthSharing_MemIdentifierMaxSize 4

#endif // PA2PrivateConstants_Included
