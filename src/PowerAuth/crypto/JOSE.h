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

#pragma once

#include <cc7/ByteArray.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
/**
 Convert ECDSA signature from DER format to JOSE. If operation fails, then returned array is empty.
 */
cc7::ByteArray  ECDSA_DERtoJOSE(const cc7::ByteRange & der_signature);

/**
 Convert ECDSA signature from JOSE to DER format. If operation fails, then returned array is empty.
 */
cc7::ByteArray  ECDSA_JOSEtoDER(const cc7::ByteRange & jose_signature);


} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io

