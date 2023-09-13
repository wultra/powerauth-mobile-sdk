/*
 * Copyright 2023 Wultra s.r.o.
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
namespace utils
{
    /**
     Concat multiple components. Each component is pointer to cc7::ByteRange object.
     */
    cc7::ByteArray ByteUtils_Concat(std::initializer_list<cc7::ByteRange> components);

    /**
     Join multiple components. Each component is pointer to cc7::ByteRange object.
     Unlike `ByteUtils_Concat` this function prepend length of each component before concatenation.
     The length is 32-bit integer with big endian byte order.
     */
    cc7::ByteArray ByteUtils_Join(std::initializer_list<cc7::ByteRange> components);
    
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
