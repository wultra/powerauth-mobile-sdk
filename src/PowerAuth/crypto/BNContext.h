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

#include <cc7/Platform.h>
#include <openssl/bn.h>

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
	 BNContext is a helper class for managing BN_CTX structure.
	 If you do not provide context then the helper will create
	 new one internally. The internally created context is
	 automatically destroyed with the BNContext object.
	 
	 The class implements casting operator to BN_CTX and
	 therefore can be easily used as a parameter to
	 functions, which requires BN_CTX.
	 */
	class BNContext
	{
	public:
		BNContext(BN_CTX * ctx = nullptr)
		{
			if (ctx == nullptr) {
				_ctx = BN_CTX_new();
				_delete_ctx = true;
			} else {
				_ctx = ctx;
				_delete_ctx = false;
			}
		}
		~BNContext()
		{
			if (_delete_ctx && _ctx) {
				BN_CTX_free(_ctx);
			}
		}
		
		// Returns internal context
		BN_CTX * ctx() const		{ return _ctx; }
		// Cast BNContext to BN_CTX pointer
		operator BN_CTX * () const	{ return _ctx; }
		
	private:
		BN_CTX * _ctx;
		bool     _delete_ctx;
	};
	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
