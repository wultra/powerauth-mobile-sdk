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

#include "DataReader.h"
#include <cc7/Endian.h>

using namespace cc7;
using namespace std;

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{
	DataReader::DataReader() :
		_offset(0)
	{
	}
	
	DataReader::DataReader(const ByteRange & data) :
		_data(data),
		_offset(0)
	{
	}
	
	DataReader::DataReader(const ByteArray & data) :
		_data_copy(data),
		_offset(0)
	{
		_data.assign(_data_copy.byteRange());
	}
	
	void DataReader::reset()
	{
		_offset = 0;
	}
	
	void DataReader::resetWithNewByteRange(const cc7::ByteRange & range)
	{
		_offset = 0;
		_data.assign(range);
		_data_copy.clear();
	}
	
	void DataReader::resetWithNewByteArray(const cc7::ByteArray &data)
	{
		_offset = 0;
		_data_copy.assign(data);
		_data.assign(_data_copy.byteRange());
	}
	
	size_t DataReader::remainingSize() const
	{
		return _data.size() - _offset;
	}
	
	size_t DataReader::currentOffset() const
	{
		return _offset;
	}
	
	bool DataReader::canReadSize(size_t size) const
	{
		return remainingSize() >= size;
	}
	
	bool DataReader::skipBytes(size_t size)
	{
		if (!canReadSize(size)) {
			return false;
		}
		_offset += size;
		return true;
	}
	
	bool DataReader::readData(ByteArray & out_data, size_t expected_size)
	{
		size_t size;
		if (!readCount(size)) {
			return false;
		}
		if (!canReadSize(size)) {
			return false;
		}
		if (expected_size > 0 && expected_size != size) {
			return false;
		}
		out_data.assign(_data.subRange(_offset, size));
		_offset += size;
		return true;
	}
	
	bool DataReader::readMemory(cc7::ByteArray & out_data, size_t size)
	{
		if (!canReadSize(size)) {
			return false;
		}
		out_data.assign(_data.subRange(_offset, size));
		_offset += size;
		return true;
	}
	
	bool DataReader::readRange(cc7::ByteRange & out_range, size_t expected_size)
	{
		size_t size;
		if (!readCount(size)) {
			return false;
		}
		if (!canReadSize(size)) {
			return false;
		}
		if (expected_size > 0 && expected_size != size) {
			return false;
		}
		out_range = _data.subRange(_offset, size);
		_offset += size;
		return true;
	}
	
	bool DataReader::readMemoryRange(cc7::ByteRange & out_range, size_t size)
	{
		if (!canReadSize(size)) {
			return false;
		}
		out_range = _data.subRange(_offset, size);
		_offset += size;
		return true;
	}
	
	bool DataReader::readString(string & out_string)
	{
		size_t size;
		if (!readCount(size)) {
			return false;
		}
		if (!canReadSize(size)) {
			return false;
		}
		out_string.assign(reinterpret_cast<const char*>(_data.data()) + _offset, size);
		_offset += size;
		return true;
	}
	
	bool DataReader::readByte(uint8_t & out_value)
	{
		if (!canReadSize(1)) {
			return false;
		}
		out_value = _data.at(_offset);
		_offset++;
		return true;
	}
	
	bool DataReader::readU16(cc7::U16 & out_value)
	{
		cc7::U16 tmp;
		if (!readRawMemory(&tmp, sizeof(tmp))) {
			return false;
		}
		out_value = FromBigEndian(tmp);
		return true;
	}
	
	bool DataReader::readU32(cc7::U32 & out_value)
	{
		cc7::U32 tmp;
		if (!readRawMemory(&tmp, sizeof(tmp))) {
			return false;
		}
		out_value = FromBigEndian(tmp);
		return true;
	}
	
	bool DataReader::readU64(cc7::U64 & out_value)
	{
		cc7::U64 tmp;
		if (!readRawMemory(&tmp, sizeof(tmp))) {
			return false;
		}
		out_value = FromBigEndian(tmp);
		return true;
	}
	
	bool DataReader::readRawMemory(void *ptr, size_t size)
	{
		if (!canReadSize(size)) {
			return false;
		}
		memcpy(ptr, _data.data() + _offset, size);
		_offset += size;
		return true;
	}
	
	bool DataReader::readCount(size_t & out_value)
	{
		byte tmp[4];
		if (!readByte(tmp[0])) {
			return false;
		}
		const byte marker = tmp[0] & 0xC0;
		if (marker == 0x00 || marker == 0x40) {
			// just one byte
			out_value = tmp[0];
			//
		} else {
			// marker is 2 or 3, that means that we need 1 or 3 more bytes
			size_t additional_bytes = marker == 0xC0 ? 3 : 1;
			if (!readRawMemory(tmp + 1, additional_bytes)) {
				return false;
			}
			if (marker == 0xC0) {
				// 4 bytes
				out_value = (size_t(tmp[0] & 0x3F) << 24) |
							(size_t(tmp[1]       ) << 16) |
							(size_t(tmp[2]	     ) << 8 ) |
							 size_t(tmp[3]);
				//
			} else {
				// 2 bytes
				out_value = (size_t(tmp[0] & 0x3F) << 8 ) |
							 size_t(tmp[1]);
				//
			}
		}
		return true;
	}
	
	// Data versioning
	
	bool DataReader::openVersion(cc7::byte expected_tag, cc7::byte min_supported_version)
	{
		cc7::byte tag = 0;
		cc7::byte version = 0;
		bool result = readByte(tag) && readByte(version);
		if (result) {
			result = tag == expected_tag && version >= min_supported_version;
			if (result) {
				_version_stack.push_back((cc7::U16(tag) << 8) | version);
			}
		}
		return result;
	}
	
	bool DataReader::closeVersion()
	{
		if (_version_stack.size() > 0) {
			_version_stack.pop_back();
			return true;
		}
		return false;
	}
	
	cc7::byte DataReader::currentTag() const
	{
		if (_version_stack.size() > 0) {
			return (_version_stack.back() >> 8);
		}
		return 0;
	}
	
	cc7::byte DataReader::currentVersion() const
	{
		if (_version_stack.size() > 0) {
			return _version_stack.back() & 0xFF;
		}
		return 0;
	}
	
} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
