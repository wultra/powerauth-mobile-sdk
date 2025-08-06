/*
 * Copyright 2025 Wultra s.r.o.
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

#include "CommonFunctions.h"
#include <PowerAuth/Types.h>
#include "../model/Constants.h"

namespace powerAuth {
namespace common {

bool IsEcKey(const cc7::crypto::Key& public_key) noexcept
{
    const auto& kt = public_key.getKeyType();
    return kt == "P-384" || kt == "P-256";
}

cc7::ByteArray ExportKeyToNormalizedForm(const cc7::crypto::PublicKey& public_key)
{
    if (!IsEcKey(public_key)) {
        return public_key.exportKey(cc7::crypto::KEY_FORMAT_SPKI);
    }
    return public_key.getKeyParameter(cc7::crypto::KEY_PARAM_EC_PUB_X).asByteRange();
}

std::string CalculateHumanReadableCodeFromHash(const cc7::ByteRange& hash, size_t code_size)
{
    if (hash.size() < 4) {
        throw Exception(EC_WrongParameter, "Hash is too short");
    }
    if (code_size < DECIMAL_AUTH_CODE_MIN_LENGTH || code_size > DECIMAL_AUTH_CODE_MAX_LENGTH) {
        throw Exception(EC_WrongParameter, "Wrong code size");
    }
    size_t offset = hash.size() - 4;
    // "dynamic binary code" from HOTP draft
    cc7::U32 dbc = (hash[offset + 0] & 0x7F) << 24 |
                    hash[offset + 1] << 16 |
                    hash[offset + 2] << 8  |
                    hash[offset + 3];
    // Convert DBC value to string
    static const cc7::U32 magnitude[] = { 10000, 100000, 1000000, 10000000, 100000000 };
    static const std::string zero("00000000");
    std::string result = std::to_string(dbc % magnitude[code_size - DECIMAL_AUTH_CODE_MIN_LENGTH]);
    if (result.length() < code_size) {
        result.insert(0, zero.substr(0, code_size - result.length()));
    }
    if (result.length() != code_size) {
        throw Exception(EC_InternalError, "Human readable code calculation is broken");
    }
    return result;
}

} // namespace common
} // namespace powerAuth
