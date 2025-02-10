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

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
    /**
     The `TLLRefObject` template helper class is responsible for capturing and managing lifetime of
     low-level reference counter objects from OpenSSL.
     */
    template <typename T, T* (*CreateFunc)(), void (*RetainFunc)(T*), void (*ReleaseFunc)(T*)> class TLLRefObject {
    public:
        
        /// Plain constructor creates an invalid object.
        TLLRefObject() : _ll_object(nullptr) {
        }
        
        // Take ownership of provided object. The reference count is not increased.
        static TLLRefObject take(T * ll_object) {
            return TLLRefObject(ll_object, false);
        }

        // Keep provided object and increase the reference count.
        static TLLRefObject ref(T * ll_object) {
            return TLLRefObject(ll_object, true);
        }
        
        // Create an invalid object.
        static TLLRefObject invalid() {
            return TLLRefObject(nullptr, false);
        }
        
        // Create an empty opbject.
        static TLLRefObject empty() {
            return TLLRefObject(CreateFunc(), false);
        }
        
        // Return low level object captured in this object.
        T * object() const {
            return _ll_object;
        }
        
        // Cast TLLObject to T pointer to use in low-level functions automatically.
        operator T * () const {
            return _ll_object;
        }
        
        // Return true if object contains valid low-level object.
        bool isValid() const {
            return _ll_object != nullptr;
        }
        
        // Copy constructor. The reference count is increased.
        TLLRefObject(const TLLRefObject & other) noexcept : _ll_object(other._ll_object) {
            if (_ll_object) {
                RetainFunc(_ll_object);
            }
        }
        
        // Move Constructor
        TLLRefObject(TLLRefObject&& other) noexcept : _ll_object(other._ll_object) {
            other._ll_object = nullptr;
        }
        
        // Copy Assignment Operator
        TLLRefObject& operator=(const TLLRefObject& other) noexcept {
            if (this != &other) {
                assign(other.object());
            }
            return *this;
        }
        
        // Move Assignment Operator
        TLLRefObject& operator=(TLLRefObject&& other) noexcept {
            if (this != &other) {
                destroy();
                _ll_object = other._ll_object;
                other._ll_object = nullptr;
            }
            return *this;
        }
        
        // Destructor
        ~TLLRefObject() {
            destroy();
        }
        
        // Destroy low level object.
        void destroy() {
            if (_ll_object) {
                ReleaseFunc(_ll_object);
                _ll_object = nullptr;
            }
        }
        
        // Assing a new low level object.
        void assign(T * ll_object) {
            destroy();
            if (ll_object) {
                _ll_object = ll_object;
                RetainFunc(_ll_object);
            }
        }
        
    private:
        
        T * _ll_object;
        
        TLLRefObject(T * ll_object, bool retain) : _ll_object(ll_object) {
            if (_ll_object && retain) {
                RetainFunc(_ll_object);
            }
        }
    };

    /**
     The `TLLObject` template helper class is responsible for capturing and managing lifetime of
     low-level objects from OpenSSL.
     
     If you do not provide pointer to low-level then the helper will create
     new one internally. The internally created context is
     automatically destroyed with the TLLObject instance.
     
     The template class implements casting operator to `T*` and therefore can be easily used as
     a parameter to functions, which requires pointet to type T.
     */
    template <typename T, T* (*CreateFunc)(), void (*ReleaseFunc)(T*)> class TLLObject {
    public:
                
        // Take ownership of provided object. The reference count is not increased.
        static TLLObject take(T * ll_object) {
            return TLLObject(ll_object, true);
        }
        
        // Capture provided low-level object without taking the ownership.
        static TLLObject wrap(T * ll_object) {
            return TLLObject(ll_object, false);
        }

        // Create an invalid object.
        static TLLObject invalid() {
            return TLLObject(nullptr, false);
        }
        
        // Create an empty object.
        static TLLObject empty() {
            return TLLObject(CreateFunc ? CreateFunc() : nullptr, true);
        }
        
        // Move Constructor
        TLLObject(TLLObject&& other) noexcept : _ll_object(other._ll_object), _delete_ll_object(other._delete_ll_object) {
            other._ll_object = nullptr;
            other._delete_ll_object = false;
        }
                
        // Move Assignment Operator
        TLLObject& operator=(TLLObject&& other) noexcept {
            if (this != &other) {
                destroy();
                _ll_object = other._ll_object;
                _delete_ll_object = other._delete_ll_object;
                other._ll_object = nullptr;
                other._delete_ll_object = false;
            }
            return *this;
        }
        
        // Destructor
        ~TLLObject() {
            destroy();
        }
        
        // Return low level object captured in this object.
        T * object() const {
            return _ll_object;
        }
        
        // Cast TLLObject to T pointer to use in low-level functions automatically.
        operator T * () const {
            return _ll_object;
        }
        
        // Return true if object contains valid low-level object.
        bool isValid() const {
            return _ll_object != nullptr;
        }
            
        void destroy() {
            if (_ll_object && _delete_ll_object) {
                ReleaseFunc(_ll_object);
                _ll_object = nullptr;
            }
            _delete_ll_object = false;
        }

    private:
        
        T *     _ll_object;
        bool    _delete_ll_object;
        
        TLLObject(T * ll_object, bool take_ownership) : _ll_object(ll_object), _delete_ll_object(take_ownership) {
        }
    };

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
