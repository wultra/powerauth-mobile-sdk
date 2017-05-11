/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#pragma once

#include <cc7/ByteArray.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
	// PA version string
	extern const std::string PA_VERSION;
	
	// PA HTTP Auth header. Contains X-PowerAuth-Authorization string
	extern const std::string PA_AUTH_HEADER_NAME;
	
	// Other header strings
	extern const std::string PA_AUTH_FRAGMENT_BEGIN_VERSION;
	extern const std::string PA_AUTH_FRAGMENT_ACTIVATION_ID;
	extern const std::string PA_AUTH_FRAGMENT_APPLICATION_KEY;
	extern const std::string PA_AUTH_FRAGMENT_NONCE;
	extern const std::string PA_AUTH_FRAGMENT_SIGNATURE_TYPE;
	extern const std::string PA_AUTH_FRAGMENT_SIGNATURE;
	extern const std::string PA_AUTH_FRAGMENT_END;
	extern const size_t      PA_AUTH_FRAGMENTS_LENGTH;
	
	// Empty IV (16 bytes filled with 0)
	extern const cc7::ByteArray ZERO_IV;
	
	// Various constant strings
	extern const std::string AMP;		// "&"
	extern const std::string DASH;		// "-"
	
	// How many iterations are used for password key derivation.
	const size_t PBKDF2_PASS_ITERATIONS = 10000;
	
	// How many iterations are used for OTP key expanding.
	const size_t PBKDF2_OTP_EXPAND_ITERATIONS = 10000;
	
	// Length of generated salt
	const size_t PBKDF2_SALT_SIZE = 16;
	
	// Length of all keys related to signature
	const size_t SIGNATURE_KEY_SIZE = 16;
	
	// Length of vault key.
	const size_t VAULT_KEY_SIZE = 16;
	
	// Minimal password length
	const size_t MINIMAL_PASSWORD_LENGTH = 4;
	
	// Length of key produced by ECDH
	const size_t SHARED_SECRET_KEY_SIZE = 32;
	
	// Length of activation nonce
	const size_t ACTIVATION_NONCE_SIZE = 16;
	
	// Length of OTP
	const size_t ACTIVATION_OTP_SIZE = 11;
	
	// Length of SHORT_ID
	const size_t ACTIVATION_SHORT_ID_SIZE = 11;
	
	// Length of decimalized signature, calculated from device public key
	const size_t HK_DEVICE_PUBLIC_KEY_SIZE = 8;
	
	// Length of status blob
	const size_t STATUS_BLOB_SIZE = 32;
	
	// Length of APPLICATION_KEY, APPLICATION_SECRET
	const size_t APPLICATION_KEY_SIZE = 16;
	const size_t APPLICATION_SECRET_SIZE = 16;
	
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
