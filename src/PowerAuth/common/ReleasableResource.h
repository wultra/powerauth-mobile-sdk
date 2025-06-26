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

#include <cc7/Platform.h>

namespace powerAuth {
namespace common {

template <typename Resource, typename Owner> class TResource
{
public:
    
};

template <typename Resource, typename Owner> class TResourceOwner : public std::enable_shared_from_this<Owner>
{
public:
    typedef TResource<Resource, Owner> TR;
    
    
};


} // namespace common
} // namespace powerAuth

