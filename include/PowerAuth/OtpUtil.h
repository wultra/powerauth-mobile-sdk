/*
 * Copyright 2016-2017 Wultra s.r.o.
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

#include <cc7/Platform.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
	/**
	 The `OtpComponents` structure contains parsed components from user-provided activation
	 code. You can use methods from `OtpUtil` class to fill this structure with valid data.
	 */
	struct OtpComponents
	{		
		/**
		 Activation code.
		 */
		std::string activationCode;
		/**
		 Signature calculated from activationCode.
		 The value is typically optional for cases, when the user re-typed activation ode
		 manually.
		 */
		std::string activationSignature;
		
		/**
		 Returns true if activationSignature contains signature.
		 */
		bool hasSignature() const;
	};
	

	/**
	 The `OtpUtil` class provides various set of methods for parsing and validating activation codes.
	 
	 Current format:
	 ------------------
	 code without signature:	CCCCC-CCCCC-CCCCC-CCCCC
	 code with signature:		CCCCC-CCCCC-CCCCC-CCCCC#BASE64_STRING_WITH_SIGNATURE
	 
	 Where the 'C' is a character from range [A-Z2-7]
	 
	 */
	class OtpUtil
	{
	public:

		// Parser
	
		/**
		 Parses an input |activation_code| (which may or may not contain an optional signature) and stores
		 the result into the |out_components| structure. The method doesn't perform an autocorrection,
		 so the provided code must be valid.
		 
		 Returns true if the code is valid and |out_components| contains a valid data.
		 */
		static bool parseActivationCode(const std::string & activation_code, OtpComponents & out_components);
		
		
		// Validations
		
		/**
		 Returns true if |utf_codepoint| is a valid character allowed in the activation code.
		 The method strictly checks whether the character is from [A-Z2-7] characters range.
		 */
		static bool validateTypedCharacter(cc7::U32 utf_codepoint);
		
		/**
		 Validates an input |utf_codepoint| as an unicode character and returns '\0' (NUL) if it's not valid or
		 cannot be corrected. The non-NUL returned value contains the same input codepoint, or the corrected one.
		 You can use this method for validation & autocorrection of just typed characters.
		 
		 The function performs following autocorections:
		 - lowercase characters are corrected to uppercase (e.g. 'a' will be corrected to 'A')
		 - '0' is corrected to 'O'
		 - '1' is corrected to 'I'
		 */
		static cc7::U32 validateAndCorrectTypedCharacter(cc7::U32 utf_codepoint);
		
		/**
		 Returns true if |activation_code| is a valid activation code. The input code must not contain a signature part.
		 You can use this method to validate a whole user-typed activation code at once.
		 */
		static bool validateActivationCode(const std::string & activation_code);
		
		/**
		 Returns true if |signature| contains a valid Base64 string.
		 */
		static bool validateSignature(const std::string & signature);

	};
	
} // io::getlime::powerAuth
} // io::getlime
} // io
