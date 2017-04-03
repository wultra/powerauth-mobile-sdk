/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#include "URLEncoding.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{
	static size_t _URLEncodingEstimateResultLength(std::string::const_iterator begin, std::string::const_iterator end)
	{
		size_t result = 0;
		bool escape = false;
		while (begin != end) {
			cc7::byte c = (cc7::byte)*begin++;
			if ((c >= '0' && c <= '9') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c == '-' || c == '_' || c == '.' || c == '*')
				)
			{
				result++;
			}
			else if (c == ' ')
			{
				result++;
				escape = true;
			}
			else
			{
				result += 3;	// %xx
				escape = true;
			}
		}
		return !escape ? 0 : result;
	}
	
	static inline cc7::byte _HexadecimalChar(cc7::byte c)
	{
		if (c < 10) {
			return c + '0';
		}
		return 'A' - 10 + c;
	}
	
	cc7::ByteArray ConvertStringToUrlEncodedData(const std::string & str)
	{
		if (str.size() == 0) {
			return cc7::ByteArray();
		}
		
		// Calculate expected length
		size_t buffer_length = _URLEncodingEstimateResultLength(str.cbegin(), str.cend());
		if (buffer_length == 0) {
			// There's no escaping, we can return input string directly.
			return cc7::ByteArray(str.cbegin(), str.cend());
		}
		
		// Prepare buffer with expected length
		cc7::ByteArray buffer;
		buffer.reserve(buffer_length);
		
		// Convert to encoded string
		auto it  = str.cbegin();
		auto end = str.cend();
		while (it != end) {
			cc7::byte c = (cc7::byte)*it++;
			if ((c >= '0' && c <= '9') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c == '-' || c == '_' || c == '.' || c == '*')
				)
			{
				// no escape
				buffer.push_back(c);
			}
			else if (c == ' ')
			{
				// space is escaped with '+'
				buffer.push_back('+');
			}
			else
			{
				// escaped characters, %XX
				buffer.push_back('%');
				buffer.push_back(_HexadecimalChar((c >> 4) & 0xf));
				buffer.push_back(_HexadecimalChar(c & 0xf));
			}
		}
		return buffer;
	}
	
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
