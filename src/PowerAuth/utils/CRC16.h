/*
 * Copyright 2018 Wultra s.r.o.
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

#include <cc7/ByteRange.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{
	/**
	 Calculates CRC-16/ARC checksum from given |bytes|
	 */
	cc7::U16 CRC16_Calculate(const cc7::ByteRange & bytes);
	
	/**
	 Validates CRC-16/ARC checksum from given |bytes|. The function is expecting
	 that the last two bytes, contains the checksum in big endian order, calculated
	 from bytes before.
	 */
	bool CRC16_Validate(const cc7::ByteRange & data);
	
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
