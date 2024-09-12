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

#include "DataWriter.h"
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

    const size_t kResetToFitThreshold = 2048;

    DataWriter::DataWriter(ByteArray * buffer)
    {
        if (buffer) {
            _data = buffer;
            _destroy_data = false;
        } else {
            _data = new ByteArray();
            _destroy_data = true;
        }
    }
    
    DataWriter::~DataWriter()
    {
        if (_destroy_data) {
            delete _data;
            _data = nullptr;
        }
    }
    
    void DataWriter::reset()
    {
        _data->clear();
        if (_data->capacity() > kResetToFitThreshold) {
            _data->shrink_to_fit();
        }
    }
    
    const ByteArray & DataWriter::serializedData() const
    {
        return *_data;
    }
    
    void DataWriter::writeData(const ByteRange & data)
    {
        if (!writeCount(data.size())) {
            return;
        }
        _data->append(data);
    }
    
    void DataWriter::writeString(const string & str)
    {
        if (!writeCount(str.size())) {
            return;
        }
        _data->append(cc7::MakeRange(str));
    }
    
    void DataWriter::writeByte(cc7::byte byte)
    {
        _data->push_back(byte);
    }
    
    void DataWriter::writeU16(cc7::U16 value)
    {
        auto tmp = ToBigEndian(value);
        writeRawMemory(&tmp, sizeof(tmp));
    }
    
    void DataWriter::writeU32(cc7::U32 value)
    {
        auto tmp = ToBigEndian(value);
        writeRawMemory(&tmp, sizeof(tmp));
    }
    
    void DataWriter::writeU64(cc7::U64 value)
    {
        auto tmp = ToBigEndian(value);
        writeRawMemory(&tmp, sizeof(tmp));
    }
    
    void DataWriter::writeMemory(const ByteRange &range)
    {
        _data->append(range);
    }
    
    //   00h ..       7Fh (as             value, one byte)
    //   80h ..     3FFFh (as     8000h | value, two bytes)
    // 4000h .. 3FFFFFFFh (as C0000000h | value, four bytes)
    
    bool DataWriter::writeCount(size_t n)
    {
        if (n <= 0x7F) {
            //
            writeByte(n);
            //
        } else if (n <= 0x3FFF) {
            //
            writeByte(((n >> 8 ) & 0x3F) | 0x80);
            writeByte(  n        & 0xFF);
            //
        } else if (n <= 0x3FFFFFFF) {
            //
            writeByte(((n >> 24) & 0x3F) | 0xC0);
            writeByte( (n >> 16) & 0xFF);
            writeByte( (n >> 8 ) & 0xFF);
            writeByte(  n        & 0xFF);
            //
        } else {
            CC7_ASSERT(false, "Count is too big.");
            return false;
        }
        return true;
    }

    bool DataWriter::writeAsn1Count(size_t n)
    {
        if (n <= 0x7F) {
            //
            writeByte(n);
            //
        } else if (n <= 0xFF) {
            //
            writeByte(0x81);
            writeByte(n);
            //
        } else if (n <= 0xFFFF) {
            //
            writeByte(0x82);
            writeU16(n);
            //
        } else if (n <= 0x3FFFFFFF) {
            //
            writeByte(0x84);
            writeU32((cc7::U32)n);
            //
        } else {
            // ASN.1 supports even bigger numbers, but it's overkill for our purpose
            CC7_ASSERT(false, "Count is too big.");
            return false;
        }
        return true;
    }
        
    size_t DataWriter::maxCount()
    {
        return 0x3FFFFFFF;
    }
    
    // Private impl.
    
    void DataWriter::writeRawMemory(const void *ptr, size_t size)
    {
        const uint8_t * p = reinterpret_cast<const uint8_t *>(ptr);
        _data->append(p, p + size);
    }
    
    // versions
    
    void DataWriter::openVersion(cc7::byte tag, cc7::byte v)
    {
        writeByte(tag);
        writeByte(v);
        _version_stack.push_back((cc7::U16(tag) << 8) | v);
    }
    
    bool DataWriter::closeVersion()
    {
        if (_version_stack.size() > 0) {
            _version_stack.pop_back();
            return true;
        }
        CC7_ASSERT(false, "Version stack is empty");
        return false;
    }
    
    cc7::byte DataWriter::currentTag() const
    {
        if (_version_stack.size() > 0) {
            return (_version_stack.back() >> 8);
        }
        CC7_ASSERT(false, "Version stack is empty");
        return 0;
    }
    
    cc7::byte DataWriter::currentVersion() const
    {
        if (_version_stack.size() > 0) {
            return _version_stack.back() & 0xFF;
        }
        CC7_ASSERT(false, "Version stack is empty");
        return 0;
    }


} // io::getlime::powerAuth::utils
} // io::getlime::powerAuth
} // io::getlime
} // io
