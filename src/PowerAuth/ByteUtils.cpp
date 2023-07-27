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

#include <PowerAuth/ByteUtils.h>
#include <cc7/Endian.h>
#include <cstdarg>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{
    cc7::ByteArray ByteUtils_Concat(std::initializer_list<cc7::ByteRange> components)
    {
        auto it = components.begin();
        size_t reserved_bytes = 0;
        while (it != components.end()) {
            reserved_bytes += it->size();
            ++it;
        }
        cc7::ByteArray result;
        result.reserve(reserved_bytes);
        it = components.begin();
        while (it != components.end()) {
            result.append(*it);
            ++it;
        }
        return result;
    }

    cc7::ByteArray ByteUtils_Join(std::initializer_list<cc7::ByteRange> components)
    {
        auto it = components.begin();
        size_t reserved_bytes = 4 * components.size();
        while (it != components.end()) {
            reserved_bytes += it->size();
            ++it;
        }
        cc7::ByteArray result;
        result.reserve(reserved_bytes);
        it = components.begin();
        while (it != components.end()) {
            auto size = cc7::ToBigEndian(cc7::U32(it->size()));
            result.append(cc7::MakeRange(size));
            result.append(*it);
            ++it;
        }
        return result;
    }
    
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
