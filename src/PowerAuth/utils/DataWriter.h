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

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{
	/**
	 The DataWriter class provides simple streaming interface usable for
	 data serialization.
	 
	 You can use DataReader as a complementary class.
	 */
	class DataWriter
	{
	public:
		/**
		 Initializes empty data writer. If you don't specify
		 out_buffer, then the internal buffer will be used.
		 */
		DataWriter(cc7::ByteArray * out_buffer = nullptr);
		
		/**
		 Destruction.
		 */
		~DataWriter();
		
		/**
		 Resets data writer object to its initial state.
		 */
		void reset();
		
		/**
		 Writes number of bytes in byte range and actual
		 data to the stream. The size of range must not exceed
		 value returned from DataWriter::maxCount() method.
		 */
		void writeData(const cc7::ByteRange & data);
		/**
		 Writes number of characters in string and actual content
		 of string to the data stream. The length of string must
		 not exceed value returned from DataWriter::maxCount() method.
		 */
		void writeString(const std::string & str);
		/**
		 Writes one byte to the stream.
		 */
		void writeByte(cc7::byte byte);
		/**
		 Writes 16 bit value to the stream.
		 */
		void writeU16(cc7::U16 value);
		/**
		 Writes 32 bit value to the stream.
		 */
		void writeU32(cc7::U32 value);
		/**
		 Writes 64 bit value to the stream.
		 */
		void writeU64(cc7::U64 value);
		
		/**
		 Writes only the content of byte range to the data stream.
		 Unlike the writeData(), thi method doesn't store number of bytes
		 as a size marker. It's up to you, how you determine the size
		 of sequence during the data reading.
		 */
		void writeMemory(const cc7::ByteRange & range);
		
		/**
		 Returns serialized data.
		 */
		const cc7::ByteArray & serializedData() const;
		
		/**
		 Writes a count to the stream in optimized binary format. The count
		 parameter must be less or equal than value returned from
		 DataWriter::maxCount(); method.
		 
		 You should prefer this method for counter-type values over the writing
		 U32 or U64 to the stream, because it usually produces a shorter byte 
		 streams. For example, if count value is lesser than 128, then just
		 one byte is serialized.
		 */
		bool writeCount(size_t count);
		
		/**
		 Returns maximum supported value which can be serialized as 
		 a counter. The returned value is the same for all supported
		 platforms and CPU architectures.
		 */
		static size_t maxCount();

		
		// Data versioning
		
		/**
		 Writes version |tag| and value |v| into the stream and
		 pushes these values into the version stack.
		 */
		void openVersion(cc7::byte tag, cc7::byte v);
		/**
		 Just pops version from the stack. Returns false if the
		 stack is already empty.
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
		 Private writeMemory implementation
		 */
		void writeRawMemory(const void * ptr, size_t size);

		cc7::ByteArray *	_data;
		VersionStack		_version_stack;
		bool				_destroy_data;
	};

} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
