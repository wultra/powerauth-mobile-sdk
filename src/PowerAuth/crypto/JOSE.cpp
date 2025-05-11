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

#include "JOSE.h"
#include "../utils/DataReader.h"
#include "../utils/DataWriter.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

// -------------------------------------------------------------------------------------------
// MARK: - ECDSA Format -
//

static bool _DecodeAsn1ByteSequence(utils::DataReader & reader, cc7::ByteRange & out_data, size_t & out_size)
{
    cc7::byte tmp;
    if (!reader.readByte(tmp) || tmp != 0x02) {
        // Invalid sequence header
        return false;
    }
    if (!reader.readAsn1Count(out_size)) {
        // Invalid size
        return false;
    }
    if (out_size > 33) {
        // Too big
        return false;
    }
    return reader.readMemoryRange(out_data, out_size);
}

cc7::ByteArray ECDSA_DERtoJOSE(const cc7::ByteRange & der_signature)
{
    cc7::ByteArray out;
    auto reader = utils::DataReader(der_signature);
    
    cc7::byte tmp;
    // Read first byte (sequence)
    if (!reader.readByte(tmp) || tmp != 0x30) {
        return out;
    }
    size_t sign_length, r_length, s_length;
    cc7::ByteRange R, S;
    if (!reader.readAsn1Count(sign_length)) {
        return out;
    }
    // Overall length should match DER length - offset
    if (sign_length != der_signature.size() - reader.currentOffset()) {
        return out;
    }
    // Read R.
    if (!_DecodeAsn1ByteSequence(reader, R, r_length)) {
        return out;
    }
    // Read S.
    if (!_DecodeAsn1ByteSequence(reader, S, s_length)) {
        return out;
    }
    
    // Everything looks fine. Now construct JOSE signature.
    out.reserve(64);
    
    // Append R
    if (r_length > 32) {
        out.append(R.subRangeFrom(r_length - 32));
    } else {
        if (r_length < 32) {
            out.append(32 - r_length, 0);
        }
        out.append(R);
    }
    // Append S
    if (s_length > 32) {
        out.append(S.subRangeFrom(s_length - 32));
    } else {
        if (s_length < 32) {
            out.append(32 - s_length, 0);
        }
        out.append(S);
    }
    return out;
}

static cc7::ByteArray _SkipPaddingBytes(const cc7::ByteRange & r)
{
    cc7::ByteArray out;
    size_t offset = 0, size = r.size();
    while (offset != size) {
        if (r[offset] != 0) {
            break;
        }
        ++offset;
    }
    // If the encoded number is negative, then keep zero byte as prefix.
    if (r[offset] > 0x7F) {
        if (offset == 0) {
            // We're already at the beginning of range, so prepend zero before the sequence
            out.push_back(0);
        } else {
            // Offset is greater than 0, so we can copy zero from the padding
            offset--;
        }
    }
    out.append(r.subRangeFrom(offset));
    return out;
}

static cc7::ByteArray _EncodeAsn1ByteSequence(utils::DataWriter & writer, const cc7::ByteRange & bytes)
{
    writer.reset();
    writer.writeByte(0x02);
    writer.writeAsn1Count(bytes.size());
    writer.writeMemory(bytes);
    return writer.serializedData();
}

cc7::ByteArray ECDSA_JOSEtoDER(const cc7::ByteRange & jose_signature)
{
    if (jose_signature.size() != 64) {
        return cc7::ByteArray();
    }
    // Split input data into half and skip zero leading bytes for each parameter.
    auto R = _SkipPaddingBytes(jose_signature.subRangeTo(32));
    auto S = _SkipPaddingBytes(jose_signature.subRangeFrom(32));
    
    auto writer = utils::DataWriter();
    auto encoded_R = _EncodeAsn1ByteSequence(writer, R);
    auto encoded_S = _EncodeAsn1ByteSequence(writer, S);
    // Encode the whole sequence
    writer.reset();
    writer.writeByte(0x30);
    writer.writeAsn1Count(encoded_R.size() + encoded_S.size());
    writer.writeMemory(encoded_R);
    writer.writeMemory(encoded_S);
    return writer.serializedData();
}

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
