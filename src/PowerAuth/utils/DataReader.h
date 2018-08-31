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
	 The DataReader class provides simple streaming interface usable for
	 data deserialization.
	 
	 You can use DataWriter as a complementary class.
	 */
	class DataReader
	{
	public:
		
		/**
		 Initializes a new empty DataReader object. You can assign data
		 for processing later, with using resetWithNewData() method.
		 */
		DataReader();
		
		/**
		 Initializes DataReader object with a ByteRange object. The ByteRange
		 must point to a valid sequence of bytes and must be valid for a whole
		 lifetime of the DataReader class.
		 */
		explicit DataReader(const cc7::ByteRange & range);
		
		/**
		 Initializes DataReader object with a ByteArray object. Unlike initialization
		 with ByteRange, this constructor makes an internal copy of provided data.
		 */
		explicit DataReader(const cc7::ByteArray & data);
		
		/**
		 Resets data reader to its initial state.
		 */
		void reset();
		
		/**
		 Resets data reader and assigns a new byte range. The ByteRange
		 must point to a valid sequence of bytes and must be valid for a whole
		 lifetime of the DataReader class.
		 */
		void resetWithNewByteRange(const cc7::ByteRange & range);
		
		/**
		 Resets data reader and assigns a new data. The metod makes copy
		 of provided data internally.
		 */
		void resetWithNewByteArray(const cc7::ByteArray & data);
		
		/**
		 Returns remaining size available in the stream.
		 */
		size_t remainingSize() const;
		
		/**
		 Returns current reading offset.
		 */
		size_t currentOffset() const;
		
		/**
		 Returns true if it's possible to read at leas |size| of bytes from stream.
		 */
		bool canReadSize(size_t size) const;
		
		/**
		 Skips required number of bytes in the stream. Returns false, if there's 
		 not enough bytes left.
		 */
		bool skipBytes(size_t size);
		
		/**
		 Reads data object into |out_data|.
		 You can specify exact |expected_size| or 0 for any size.
		 */
		bool readData(cc7::ByteArray & out_data, size_t expected_size = 0);
		
		/**
		 Reads exact number of bytes into |out_data|.
		 Unlike the readData(), this method reads just exact number of bytes
		 from the stream, without any size marker.
		 */
		bool readMemory(cc7::ByteArray & out_data, size_t size);
		
		/**
		 Similar to readData(), but returns sub-range to internal data object.
		 */
		bool readRange(cc7::ByteRange & out_range, size_t expected_size = 0);

		/**
		 Similar to readMemory() method, but returns just a sub-range to 
		 internal data object;
		 */
		bool readMemoryRange(cc7::ByteRange & out_range, size_t size);
		
		/**
		 Reads string object into |out_string|
		 */
		bool readString(std::string & out_string);
		/**
		 Reads one byte into |out_value|
		 */
		bool readByte(cc7::byte & out_value);
		/**
		 Reads one 16 bit value into |out_value|
		 */
		bool readU16(cc7::U16 & out_value);
		/**
		 Reads one 32 bit value into |out_value|
		 */
		bool readU32(cc7::U32 & out_value);
		/**
		 Reads one 64 bit value into |out_value|
		 */
		bool readU64(cc7::U64 & out_value);
		
		/**
		 Returns count from data stream. This is complementary method
		 to DataWriter::writeCount().
		 */
		bool readCount(size_t & out_value);
		
		// Data versioning
		
		/**
		 Opens versioned data section. You have to provide expected data tag and minimum
		 supported data version.
		 */
		bool openVersion(cc7::byte expected_tag, cc7::byte min_supported_version);
		/**
		 Closes versioned data section. This operation simply pops current version from the
		 stack of versions. Returns false if stack is already empty.
		 */
		bool closeVersion();

		/**
		 Returns top version tag from the version stack.
		 If the tag is empty, then returns 0;
		 */
		cc7::byte currentTag() const;
		/**
		 Returns top version value from the version stack.
		 If the tag is empty, then returns 0;
		 */
		cc7::byte currentVersion() const;

		
	private:
		
		typedef std::vector<cc7::U16> VersionStack;
		
		/**
		 Reads exact amount of bytes to the given buffer.
		 */
		bool readRawMemory(void * ptr, size_t size);
		
		cc7::ByteRange	_data;
		cc7::ByteArray	_data_copy;
		size_t			_offset;
		VersionStack	_version_stack;
	};
	
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
