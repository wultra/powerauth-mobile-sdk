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


#include <PowerAuth/OtpUtil.h>
#include <cc7/Base64.h>
#include <cc7/Base32.h>
#include "utils/CRC16.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
    
    // MARK: - OtpComponents -
    
    bool OtpComponents::hasSignature() const
    {
        return !activationSignature.empty();
    }
    
    // MARK: - OtpUtil -
    
    // Parser
    
    bool OtpUtil::parseActivationCode(const std::string &activationCode, OtpComponents &out_components)
    {
        // At first, look for #
        auto hash_pos = activationCode.find('#');
        auto has_signature = hash_pos != std::string::npos;
        if (has_signature) {
            // split activationCode to code and signature
            out_components.activationCode = activationCode.substr(0, hash_pos);
            out_components.activationSignature = activationCode.substr(hash_pos + 1);
            // validate Base64 signature
            if (!validateSignature(out_components.activationSignature)) {
                return false;
            }
        } else {
            // use a whole input string as a code
            out_components.activationCode = activationCode;
            out_components.activationSignature.clear();
        }
        // Now validate just the code
        return validateActivationCode(out_components.activationCode);
    }
    
    static const std::string RECOVERY_QR_MARKER("R:");
    
    bool OtpUtil::parseRecoveryCode(const std::string &recovery_code, OtpComponents &out_components)
    {
        std::string code_to_test;
        auto recovery_marker_pos = recovery_code.find(RECOVERY_QR_MARKER);
        if (recovery_marker_pos != std::string::npos) {
            if (recovery_marker_pos != 0) {
                return false;   // "R:" is not at the beginning of string
            }
            code_to_test = recovery_code.substr(2);
        } else {
            code_to_test = recovery_code;
        }
        if (!parseActivationCode(code_to_test, out_components)) {
            return false;
        }
        return out_components.hasSignature() == false;
    }
    
    
    // Validations

    bool OtpUtil::validateTypedCharacter(cc7::U32 uc)
    {
        return (uc >= 'A' && uc <= 'Z') || (uc >= '2' && uc <= '7');
    }
    
    
    cc7::U32 OtpUtil::validateAndCorrectTypedCharacter(cc7::U32 uc)
    {
        // If character is already valid, then return it directly
        if (validateTypedCharacter(uc)) {
            return uc;
        }
        // autocorrect
        if (uc >= 'a' && uc <= 'z') {
            return uc - ('a' - 'A');    // lower->upper case
        } else  if (uc == '0') {
            return 'O';                 // 0 -> O
        } else if (uc == '1') {
            return 'I';                 // 1 -> I
        }
        // character is invalid
        return 0;
    }
    
    
    bool OtpUtil::validateActivationCode(const std::string &code)
    {
        // ABCDE-ABCDE-ABCDE-ABCDE
        if (code.length() != 23) {
            return false;
        }
        std::string code_base32;
        code_base32.reserve(20);
        for (size_t i = 0; i < code.length(); i++) {
            auto c = code[i];
            // validate dash at right position
            if ((i % 6) == 5) {
                if (c != '-') {
                    return false;
                }
            } else {
                code_base32.push_back(c);
            }
        }
        cc7::ByteArray code_bytes;
        if (!cc7::Base32_Decode(code_base32, false, code_bytes)) {
            // Not a valid Base32 string
            return false;
        }
        // Finally, validate CRC-16 checksum
        return utils::CRC16_Validate(code_bytes);
    }
    
    
    bool OtpUtil::validateSignature(const std::string &signature)
    {
        cc7::ByteArray foo_data;
        if (cc7::Base64_Decode(signature, 0, foo_data)) {
            return !foo_data.empty();
        }
        return false;
    }
    
    
    bool OtpUtil::validateRecoveryCode(const std::string &recovery_code, bool allow_r_prefix)
    {
        if (recovery_code.find(RECOVERY_QR_MARKER) == std::string::npos) {
            return validateActivationCode(recovery_code);
        }
        return allow_r_prefix && validateActivationCode(recovery_code.substr(2));
    }
    
    
    bool OtpUtil::validateRecoveryPuk(const std::string &recovery_puk)
    {
        if (recovery_puk.length() != 10) {
            return false;
        }
        for (size_t i = 0; i < recovery_puk.length(); i++) {
            auto c = recovery_puk[i];
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
    
} // io::getlime::powerAuth
} // io::getlime
} // io
