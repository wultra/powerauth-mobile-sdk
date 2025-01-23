/*
 * Copyright 2025 Wultra s.r.o.
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
     The `TLLObject` template helper class is responsible for capturing and managing lifetime of
     low-level objects from OpenSSL.
     
     If you do not provide pointer to low-level then the helper will create
     new one internally. The internally created context is
     automatically destroyed with the TLLObject instance.
     
     The template class implements casting operator to `T*` and therefore can be easily used as
     a parameter to functions, which requires pointet to type T.
     */
    template <typename T, T* (*CreateFunc)(), void (*DestroyFunc)(T*)> class TLLObject {
    public:
        
        TLLObject(T * ll_object = nullptr, bool always_destroy = false) {
            if (ll_object) {
                _ll_object = ll_object;
                _delete_ll_object = always_destroy;
            } else {
                _ll_object = CreateFunc();
                _delete_ll_object = true;
            }
        }
        
        ~TLLObject() {
            if (_delete_ll_object && _ll_object) {
                DestroyFunc(_ll_object);
            }
        }
        
        // Return low level object captured in this object.
        T * object() const {
            return _ll_object;
        }
        
        // Cast TLLObject to T pointer to use in low-level functions automatically.
        operator T * () const {
            return _ll_object;
        }
        
    private:
        T *     _ll_object;
        bool    _delete_ll_object;
    };
    
    /// The `BNContext` is wrapper for `BN_CTX`.
    typedef TLLObject<BN_CTX, BN_CTX_new, BN_CTX_free> BNContext;

    

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
