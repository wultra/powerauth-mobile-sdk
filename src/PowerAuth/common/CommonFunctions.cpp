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

cc7::ByteArray NormalizeDataForAuthCodeCalculation(const std::string_view & method,
                                                   const std::string_view & uri,
                                                   const std::string_view & nonce_b64,
                                                   const cc7::ByteRange & body,
                                                   const std::string_view & app_secret)
{
    std::string body_b64 = body.base64();
    std::string uri_b64  = cc7::MakeRange(uri).base64();
    
    cc7::ByteArray data_for_signing;
    data_for_signing.reserve(method.size() + uri_b64.size() + nonce_b64.size() + body_b64.size() + app_secret.size() + 5);
    
    // Construct data for signing
    data_for_signing.assign(method.begin(), method.end());
    data_for_signing.push_back('&');
    data_for_signing.append(uri_b64.begin(), uri_b64.end());
    data_for_signing.push_back('&');
    data_for_signing.append(nonce_b64.begin(), nonce_b64.end());
    data_for_signing.push_back('&');
    data_for_signing.append(body_b64.begin(), body_b64.end());
    data_for_signing.push_back('&');
    data_for_signing.append(app_secret.begin(), app_secret.end());
    
    return data_for_signing;
}

int CalculateDistanceBetweenByteCounters(cc7::byte local_ctr, cc7::byte server_ctr)
{
    int L = local_ctr;
    int S = server_ctr;
    // Calculate possible distances
    int d1 = L - S;
    int d2 = 256 + L - S;
    int d3 = L - (256 + S);
    // Find minimum absolute distance from possible distances
    int d1a = abs(d1);
    int d2a = abs(d2);
    int d3a = abs(d3);
    int distance_abs = std::min(d1a, std::min(d2a, d3a));
    // Determine which one is it.
    if (distance_abs == d1a) {
        return d1;
    } else if (distance_abs == d2a) {
        return d2;
    }
    return d3;
}

} // namespace common
} // namespace powerAuth
