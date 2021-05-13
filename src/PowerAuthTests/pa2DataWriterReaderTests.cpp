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

#include <cc7tests/CC7Tests.h>
#include "utils/DataReader.h"
#include "utils/DataWriter.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;
using namespace io::getlime::powerAuth::utils;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2DataWriterReaderTests : public UnitTest
	{
	public:
		
		pa2DataWriterReaderTests()
		{
			CC7_REGISTER_TEST_METHOD(testReadWriteCount)
			CC7_REGISTER_TEST_METHOD(testReadWriteMethods)
			CC7_REGISTER_TEST_METHOD(testNotEnoughData)
			CC7_REGISTER_TEST_METHOD(testVersions)
		}
		
		// unit tests
		
		/*
		 The test validates writeCount() / readCount() functionality
		 */
		void testReadWriteCount()
		{
			size_t test_value = 1;
			size_t restored_value;
			bool simulated_failure_passed = false;
			while (test_value <= ((size_t)-1)/2) {
				
				DataWriter writer;
				bool write_result = writer.writeCount(test_value);
				DataReader reader(writer.serializedData());
				bool read_result = reader.readCount(restored_value);
				
				if (test_value <= DataWriter::maxCount()) {
					// Values should be correct
					ccstAssertTrue(write_result);
					ccstAssertTrue(read_result);
					ccstAssertEqual(reader.remainingSize(), 0);
					ccstAssertEqual(test_value, restored_value, "Restored: 0x%x, Expected 0x%x", restored_value, test_value);
				} else {
					ccstAssertFalse(write_result);
					// read result is not important
					simulated_failure_passed = true;
				}
				
				// Calculate next test value
				if (test_value & 1) {
					test_value += 1;
				} else {
					test_value = (test_value << 1) - 1;
				}
			}
			// There must be at least one pass when write_result is false.
			ccstAssertTrue(simulated_failure_passed, "Max value not tested properly.");
		}
		
		void readWriteSequenceTest(ByteArray * arr)
		{
			if (arr) {
				ccstMessage("Testing with provided array.");
			} else {
				ccstMessage("Testing with internal array.");
			}
			
			ByteArray randomData_32   = getTestRandomData(32);
			ByteArray randomData_177  = getTestRandomData(177);
			ByteArray randomData_1337 = getTestRandomData(1337);
			std::string string_small("Hello world!");
			std::string string_big("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
								   "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
								   "enim ad minim veniam, quis nostrud exercitation ullamco laboris"
								   " nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor"
								   " in reprehenderit in voluptate velit esse cillum dolore eu fugiat"
								   " nulla pariatur. Excepteur sint occaecat cupidatat non proident,"
								   " sunt in culpa qui officia deserunt mollit anim id est laborum.");
			
			DataWriter writer(arr);
			{
				writer.writeData(randomData_32);
				writer.writeData(randomData_177);
				writer.writeMemory(randomData_1337);
				
				writer.writeU16(0xCCDD);
				writer.writeString(string_big);
				writer.writeU32(0x12345678);
				writer.writeU64(0x12345678ccddeeffLL);
				writer.writeString(string_small);
				writer.writeByte(0xEE);
				
			}
			
			DataReader reader(writer.serializedData());
			{
				ByteArray receivedData_32;
				ByteArray receivedData_177;
				ByteArray receivedData_1337;
				U16 received_U16 = 0;
				U32 received_U32 = 0;
				U64 received_U64 = 0;
				std::string received_big_string;
				std::string received_small_string;
				byte tag = 0;
				
				bool result = true;
				result = result && reader.readData(receivedData_32);
				ccstAssertTrue(result);
				ccstAssertEqual(receivedData_32, randomData_32);
				
				result = result && reader.readData(receivedData_177);
				ccstAssertTrue(result);
				ccstAssertEqual(receivedData_177, randomData_177);
				
				result = result && reader.readMemory(receivedData_1337, randomData_1337.size());
				ccstAssertTrue(result);
				ccstAssertEqual(receivedData_1337, randomData_1337);
				
				result = result && reader.readU16(received_U16);
				ccstAssertTrue(result);
				ccstAssertEqual(received_U16, 0xCCDD);
			
				result = result && reader.readString(received_big_string);
				ccstAssertTrue(result);
				ccstAssertEqual(received_big_string, string_big);
				
				result = result && reader.readU32(received_U32);
				ccstAssertTrue(result);
				ccstAssertEqual(received_U32, 0x12345678);
				
				result = result && reader.readU64(received_U64);
				ccstAssertTrue(result);
				ccstAssertEqual(received_U64, 0x12345678ccddeeffL);
				
				result = result && reader.readString(received_small_string);
				ccstAssertTrue(result);
				ccstAssertEqual(received_small_string, string_small);
				
				result = result && reader.readByte(tag);
				ccstAssertTrue(result);
				ccstAssertEqual(tag, 0xEE);
				ccstAssertEqual(reader.remainingSize(), 0);
			}
		}
		
		void testReadWriteMethods()
		{
			ByteArray temp;
			readWriteSequenceTest(&temp);
			readWriteSequenceTest(nullptr);
		}
		
		// Negative scenarios
		
		void testNotEnoughData()
		{
			{
				DataReader reader;
				byte foo_byte;
				U16 foo_u16;
				U32 foo_u32;
				U64 foo_u64;
				std::string foo_string;
				ByteArray foo_array;

				ccstAssertFalse(reader.readByte(foo_byte));
				ccstAssertFalse(reader.readU16(foo_u16));
				ccstAssertFalse(reader.readU32(foo_u32));
				ccstAssertFalse(reader.readU64(foo_u64));
				ccstAssertFalse(reader.readString(foo_string));
				ccstAssertFalse(reader.readData(foo_array));
				ccstAssertFalse(reader.readMemory(foo_array, 1));
				
				ByteArray bytes_1(1, 0xff);
				ByteArray bytes_2(2, 0xff);
				ByteArray bytes_3(3, 0xff);
				ByteArray bytes_7(7, 0xff);
				
				reader.resetWithNewByteArray(bytes_1);

				ccstAssertFalse(reader.readU16(foo_u16));
				ccstAssertFalse(reader.readU32(foo_u32));
				ccstAssertFalse(reader.readU64(foo_u64));
				ccstAssertFalse(reader.readString(foo_string));
				ccstAssertFalse(reader.readData(foo_array));
				ccstAssertFalse(reader.readMemory(foo_array, 2));
				
				reader.resetWithNewByteArray(bytes_2);
				ccstAssertFalse(reader.readU32(foo_u32));
				ccstAssertFalse(reader.readU64(foo_u64));
				ccstAssertFalse(reader.readString(foo_string));
				ccstAssertFalse(reader.readData(foo_array));
				ccstAssertFalse(reader.readMemory(foo_array, 3));

				reader.resetWithNewByteArray(bytes_3);
				ccstAssertFalse(reader.readU32(foo_u32));
				ccstAssertFalse(reader.readU64(foo_u64));
				ccstAssertFalse(reader.readString(foo_string));
				ccstAssertFalse(reader.readData(foo_array));
				ccstAssertFalse(reader.readMemory(foo_array, 4));
				
				reader.resetWithNewByteArray(bytes_7);
				ccstAssertFalse(reader.readU64(foo_u64));
				ccstAssertFalse(reader.readString(foo_string));
				ccstAssertFalse(reader.readData(foo_array));
				ccstAssertFalse(reader.readMemory(foo_array, 6));

			}
			{
				// readCount() when there's not enough data
				DataWriter writer;
				DataReader reader;
				size_t foo_size;

				writer.writeCount(127);
				ccstAssertTrue(writer.serializedData().size() == 1);
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(0));
				ccstAssertFalse(reader.readCount(foo_size));
				
				writer.reset();
				writer.writeCount(129);
				ccstAssertTrue(writer.serializedData().size() == 2);
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(0));
				ccstAssertFalse(reader.readCount(foo_size));
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(1));
				ccstAssertFalse(reader.readCount(foo_size));
				
				writer.reset();
				writer.writeCount(65536);
				ccstAssertTrue(writer.serializedData().size() == 4);
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(0));
				ccstAssertFalse(reader.readCount(foo_size));
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(1));
				ccstAssertFalse(reader.readCount(foo_size));
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(2));
				ccstAssertFalse(reader.readCount(foo_size));
				reader.resetWithNewByteRange(writer.serializedData().byteRange().subRangeTo(3));
				ccstAssertFalse(reader.readCount(foo_size));
			}
			
		}
		
		
		// Data versioning
		
		void testVersions()
		{
			bool result;
			
			DataWriter writer;
			writer.openVersion('T', 1);
			ccstAssertTrue(writer.currentTag() == 'T');
			ccstAssertTrue(writer.currentVersion() == 1);
			// write some data...
			writer.writeU32(0xccddeeff);
			
			writer.openVersion('F', 2);
			ccstAssertTrue(writer.currentTag() == 'F');
			ccstAssertTrue(writer.currentVersion() == 2);
			
			writer.writeU32(0x11223344);
			
			result = writer.closeVersion();
			ccstAssertTrue(result);
			ccstAssertTrue(writer.currentTag() == 'T');
			ccstAssertTrue(writer.currentVersion() == 1);
			
			result = writer.closeVersion();
			ccstAssertTrue(result);
			result = writer.closeVersion();
			ccstAssertFalse(result);
			
			writer.openVersion('X', 3);
			ccstAssertTrue(writer.currentTag() == 'X');
			ccstAssertTrue(writer.currentVersion() == 3);
			writer.closeVersion();
			
			ccstAssertTrue(writer.currentVersion() == 0);
			ccstAssertTrue(writer.currentTag() == 0);

			
			DataReader reader(writer.serializedData().byteRange());
			
			result = reader.openVersion('T', 1);
			ccstAssertTrue(result);
			ccstAssertTrue(reader.currentTag() == 'T');
			ccstAssertTrue(reader.currentVersion() == 1);
			cc7::U32 payload;
			result = reader.readU32(payload);
			ccstAssertTrue(result);
			ccstAssertTrue(payload == 0xccddeeff);
			
			result = reader.openVersion('F', 1);
			ccstAssertTrue(result);
			ccstAssertTrue(reader.currentTag() == 'F');
			ccstAssertTrue(reader.currentVersion() == 2);

			result = reader.readU32(payload);
			ccstAssertTrue(result);
			ccstAssertTrue(payload == 0x11223344);

			result = reader.closeVersion();
			ccstAssertTrue(result);
			ccstAssertTrue(reader.currentTag() == 'T');
			ccstAssertTrue(reader.currentVersion() == 1);
			
			result = reader.closeVersion();
			ccstAssertTrue(result);
			
			result = reader.openVersion('X', 4);
			ccstAssertFalse(result);	// must fail, min version cond. is not met
			
			ccstAssertTrue(reader.currentVersion() == 0);
			ccstAssertTrue(reader.currentTag() == 0);

			// keep writer on the stack...
			writer.reset();
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2DataWriterReaderTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
