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

#include "OSSLObjects.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

cc7::ByteArray BigNum_ToArray(const BigNum & bn)
{
    cc7::ByteArray array;
    array.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, array.data());
    return array;
}

BigNum BigNum_FromArray(const cc7::ByteArray & array)
{
    return BigNum::take(BN_bin2bn(array.data(), (int)array.size(), nullptr));
}

void EVPKeyPairRefUp(EVP_PKEY * pkey)
{
    EVP_PKEY_up_ref(pkey);
}

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
