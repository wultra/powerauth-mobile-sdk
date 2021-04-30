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

#ifndef PA2PrivateConstants_Included
#define PA2PrivateConstants_Included

// The following constants still contains "PA2Error*" codes, to maintain a full compatibility with watchOS.
#define PA2Def_PowerAuthErrorDomain					@"PA2ErrorDomain"
#define PA2Def_PowerAuthErrorInfoKey_AdditionalInfo	@"PA2ErrorInfoKey_AdditionalInfo"
#define PA2Def_PowerAuthErrorInfoKey_ResponseData	@"PA2ErrorInfoKey_ResponseData"

// PA2Keychain constants

#define PA2Def_PowerAuthKeychainKey_Possession		@"PA2KeychainKey_Possession"
#define PA2Def_PowerAuthKeychain_Initialized		@"io.getlime.PowerAuthKeychain.Initialized"
#define PA2Def_PowerAuthKeychain_Status				@"io.getlime.PowerAuthKeychain.StatusKeychain"
#define PA2Def_PowerAuthKeychain_Possession			@"io.getlime.PowerAuthKeychain.PossessionKeychain"
#define PA2Def_PowerAuthKeychain_Biometry			@"io.getlime.PowerAuthKeychain.BiometryKeychain"
#define PA2Def_PowerAuthKeychain_TokenStore			@"io.getlime.PowerAuthKeychain.TokenStore"

#endif // PA2PrivateConstants_Included
