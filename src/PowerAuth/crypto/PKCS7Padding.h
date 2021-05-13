/*
 * Copyright 2021 Wultra s.r.o.
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

/*
 Note that all functionality provided by this header will
 be replaced with a similar cc7 implementation.
 */

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
	/**
	 Adds a PKCS7 padding to given SafeData object.
	 */
	void PKCS7_Add(cc7::ByteArray & inout_data, size_t padding_size);
	
	/**
	 Adds a PKCS7 padding to given SafeData object and returns new instance of SafeData object
	 with padded data.
	 */
	cc7::ByteArray PKCS7_GetPaddedData(const cc7::ByteRange & data, size_t padding_size);
	
	/**
	 Validates PKCS7 padding in given data object. Returns how many bytes were added or 0
	 if error.
	 */
	size_t PKCS7_Validate(const cc7::ByteRange & data, size_t padding_size);
	
	/**
	 Validates PKCS7 padding in given data object and updates its size if padding is valid.
	 */
	bool PKCS7_ValidateAndUpdateData(cc7::ByteArray & inout_data, size_t padding_size);

	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
