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
    /**
     The Password class implements simple class for wrapping
     and manipulating with an user's passphrase. 
     
     Note that unlike the high level interfaces, this low level 
     C++ implementation supports both mutable and immutable passphrases.
     The immutability depends only on how the object was initialized
     for the last time.
     */
    class Password
    {
    public:
        
        // MARK: - Construction, Destruction -
        
        /**
         Constructs a new empty, immutable password.
         */
        Password();
        /**
         Destructs password object.
         */
        ~Password();
        
        /**
         Initializes object for immutable password data.
         The existing password is replaced with content of data.
         */
        void initAsImmutable(const cc7::ByteRange & data);
        
        /**
         Initializes object for mutable password.
         The existing password is removed.
         */
        void initAsMutable();
        
        
        // MARK: - Immutable operations -
        
        /**
         Returns true if password was initialized as mutable.
         */
        bool isMutable() const;
        
        /**
         If password is immutable, then returns lenght of password in bytes.
         If password is mutable, then returns number of characters stored in the password.
         */
        size_t length() const;
        
        /**
         Returns reference to plaintext password data.
         */
        const cc7::ByteArray & passwordData() const;
        
        /**
         Returns true when both objects contains equal passphrase.
         */
        bool isEqualToPassword(const Password & p) const;
        
        
        // MARK: - Mutable operations -
        
        /**
         Clears content of password. Returns false only if the object
         was initialized as immutable.
         */
        bool clear();
        
        /**
         Adds one unicode code point at the end of passphrase.
         Returns true if operation succeeded or false if object is not
         mutable, or code point is invalid.
         */
        bool addCharacter(cc7::U32 utf_codepoint);
        
        /**
         Inserts unicode code point at the desired index.
         Returns true if operation succeeded or false if object is not
         mutable, or code point is invalid, or index is out of the range.
         */
        bool insertCharacter(cc7::U32 utf_codepoint, size_t index);
        
        /**
         Removes last unicode code point from the passphrase.
         Returns true if operation succeeded or false if object is not 
         mutable, or passphrase is already empty.
         */
        bool removeLastCharacter();
        
        /**
         Removes character from desired index.
         Returns true if operation succeeded or false if object is not
         mutable, or index is out of the range.
         */
        bool removeCharacter(size_t index);
        
    private:
        
        // MARK: - Private section -
        
        typedef std::vector<size_t> PosVector;
        
        /**
         Passphrase
         */
        cc7::ByteArray  _pass;
        
        /**
         Character positions, valid only for mutable instances.
         */
        PosVector *     _char_pos;
        
        /**
         In mutable object, converts character index into position to 
         _pass array.
         */
        size_t indexToPos(size_t index);
        
        /**
         Updates all offsets in_char_pos array, from begin index
         to the end of the vector.
         */
        void updateIndexes(size_t begin, ptrdiff_t offset);
        
    };
    
    
    

    
} // io::getlime::powerAuth
} // io::getlime
} // io
