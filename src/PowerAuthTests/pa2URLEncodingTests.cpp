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

#include <cc7tests/CC7Tests.h>
#include "utils/URLEncoding.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2URLEncodingTests : public UnitTest
	{
	public:
		
		pa2URLEncodingTests()
		{
			CC7_REGISTER_TEST_METHOD(testEncoding)
		}
		
		void testEncoding()
		{
			const struct {
				const char * source;
				const char * expected;
			} tests[] =
			{
				{
					"", ""
				},
				{
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				},
				{
					"abcdefghijklmnopqrstuvwxyz",
					"abcdefghijklmnopqrstuvwxyz"
				},
				{
					"1234567890-_.!~*'( )",
					"1234567890-_.%21%7E*%27%28+%29"
				},
				{
					"        ",
					"++++++++"
				},
				{
					"\x01\x02\x03\x04\x05\x06\xAA\xBB\xCC\xDD\x1E\xE1\xFE\xEF",
					"%01%02%03%04%05%06%AA%BB%CC%DD%1E%E1%FE%EF"
				},
				{
					u8"Jednou z dôležitých vlastností korpusov je ich reprezentatívnosť.",
					"Jednou+z+d%C3%B4le%C5%BEit%C3%BDch+vlastnost%C3%AD+korpusov+je+ich+reprezentat%C3%ADvnos%C5%A5."
				},
				{
					u8"Referenční korpus je stálý, takže opakované dotazy dávají vždy stejné výsledky.",
					"Referen%C4%8Dn%C3%AD+korpus+je+st%C3%A1l%C3%BD%2C+tak%C5%BEe+opakovan%C3%A9+dotazy+d%C3%A1vaj%C3%AD+v%C5%BEdy+stejn%C3%A9+v%C3%BDsledky."
				},
				// end
				{
					nullptr, nullptr
				}
			};
			
			auto td = tests;
			while (td->source) {
				cc7::ByteArray result   = utils::ConvertStringToUrlEncodedData(std::string(td->source));
				cc7::ByteArray expected = cc7::MakeRange(td->expected);
				ccstAssertEqual(result, expected);
				td++;
			}
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2URLEncodingTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
