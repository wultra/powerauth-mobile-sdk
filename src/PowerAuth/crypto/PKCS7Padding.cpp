/*
 * Copyright 2016-2017 Wultra s.r.o.
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

#include "PKCS7Padding.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
	
	void PKCS7_Add(cc7::ByteArray & inout_data, size_t padding_size)
	{
		size_t additional_bytes = padding_size - (inout_data.size() & (padding_size - 1));
		if (!additional_bytes) {
			additional_bytes = padding_size;
		}
		inout_data.insert(inout_data.end(), additional_bytes, additional_bytes & 0xff);
	}
	
	cc7::ByteArray PKCS7_GetPaddedData(const cc7::ByteRange & data, size_t padding_size)
	{
		cc7::ByteArray result(data);
		PKCS7_Add(result, padding_size);
		return result;
	}
	
	size_t PKCS7_Validate(const cc7::ByteRange & data, size_t padding_size)
	{
		if (data.size() < padding_size) {
			// data must contain at least padding bytes.
			return 0;
		}
		if ((data.size() & (padding_size - 1)) != 0) {
			// size must be aligned to padding
			return 0;
		}
		uint8_t additional_bytes = data[data.size() - 1];
		if (additional_bytes > padding_size || additional_bytes == 0) {
			// padding value in payload is higher than required padding or is 0
			return 0;
		}
		if (additional_bytes > data.size()) {
			// padding value in payload is higher than actual size of data
			return 0;
		}
		// Now validate a whole padding sequence
		for (size_t index = data.size() - additional_bytes; index < data.size() - 1; index++) {
			if (data[index] != additional_bytes) {
				// wrong padding scheme
				return 0;
			}
		}
		return additional_bytes;
	}
	
	bool PKCS7_ValidateAndUpdateData(cc7::ByteArray & inout_data, size_t padding_size)
	{
		size_t additional_data = PKCS7_Validate(inout_data, padding_size);
		if (additional_data == 0) {
			return false;
		}
		inout_data.resize(inout_data.size() - additional_data);
		return true;
	}

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
