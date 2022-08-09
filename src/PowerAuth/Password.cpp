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

#include <PowerAuth/Password.h>
#include <iterator>
#include "crypto/PRNG.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
    /**
     Converts one UTF codepoint into sequence of UTF8 encoded bytes.
     */
    static bool _UTF8Encode(cc7::U32 codepoint, cc7::ByteArray & out)
    {
        cc7::byte buffer[4];
        if(codepoint < 0x80) {
            buffer[0] = (char)codepoint;
            out.append(buffer, 1);
        } else if(codepoint < 0x800) {
            buffer[0] = 0xC0 + ((codepoint & 0x7C0) >> 6);
            buffer[1] = 0x80 + ((codepoint & 0x03F));
            out.append(buffer, 2);
        } else if(codepoint < 0x10000) {
            buffer[0] = 0xE0 + ((codepoint & 0xF000) >> 12);
            buffer[1] = 0x80 + ((codepoint & 0x0FC0) >> 6);
            buffer[2] = 0x80 + ((codepoint & 0x003F));
            out.append(buffer, 3);
        } else if(codepoint <= 0x10FFFF) {
            buffer[0] = 0xF0 + ((codepoint & 0x1C0000) >> 18);
            buffer[1] = 0x80 + ((codepoint & 0x03F000) >> 12);
            buffer[2] = 0x80 + ((codepoint & 0x000FC0) >> 6);
            buffer[3] = 0x80 + ((codepoint & 0x00003F));
            out.append(buffer, 4);
        } else {
            return false;
        }
        return true;
    }
    
    
    // MARK: - Construction / Destruction -
    
    Password::Password() :
        _char_pos(nullptr)
    {
    }
    
    Password::~Password()
    {
        delete _char_pos;
    }
    
    
    // MARK: - Initialization -
    
    void Password::initAsImmutable(const cc7::ByteRange & data)
    {
        delete _char_pos;
        _char_pos = nullptr;
        // We're very paranoid here, Let's clear previous content
        // and assign new one
        _pass.secureClear();
        _pass.assign(crypto::GetRandomData(randomKeySize * 2));
        _pass.resize(randomKeySize);
        // Now append the plaintext data
        _pass.append(data);
        // And finally, hide the stored content.
        inplaceXor(randomKeySize);
    }
    
    void Password::initAsMutable()
    {
        if (_char_pos) {
            _char_pos->clear();
        } else {
            _char_pos = new PosVector();
        }
        _pass.secureClear();
        // Generate twice as required random bytes
        _pass.assign(crypto::GetRandomData(randomKeySize * 2));
        // Resize buffer to randomKeySize, so the mutable
        // password will be empty.
        _pass.resize(randomKeySize);
    }
    
    
    // MARK: - Immutable methods -
    
    bool Password::isMutable() const
    {
        return _char_pos != nullptr;
    }
    
    size_t Password::length() const
    {
        if (isMutable()) {
            return _char_pos->size();
        } else {
            return _pass.size() - randomKeySize;
        }
    }
    
    cc7::ByteArray Password::passwordData() const
    {
        // Pre-allos result ByteArray with actual stored data size.
        const size_t data_size = _pass.size() - randomKeySize;
        cc7::ByteArray plaintext(data_size);
        // Reveal plaintext bytes to result ByteArray
        for (size_t offset = 0; offset < data_size; ++offset) {
            plaintext[offset] = _pass[offset % randomKeySize] ^ _pass[offset + randomKeySize];
        }
        return plaintext;
    }
    
    bool Password::isEqualToPassword(const Password & p) const
    {
        return passwordData() == p.passwordData();
    }
    
    
    // MARK: - Mutable operations -
    
    bool Password::clear()
    {
        if (isMutable()) {
            initAsMutable();
            return true;
        }
        return false;
    }
    
    bool Password::addCharacter(cc7::U32 utf_codepoint)
    {
        if (isMutable()) {
            cc7::ByteArray bytes;
            bytes.reserve(4);
            if (CC7_CHECK(_UTF8Encode(utf_codepoint, bytes), "Wrong codepoint")) {
                // store current position (e.g. current size of pass)
                size_t offset = _pass.size();
                _char_pos->push_back(offset);
                // append bytes...
                _pass.append(bytes);
                // Hide bytes from offset to the end
                inplaceXor(offset);
                return true;
            }
        }
        return false;
    }
    
    bool Password::insertCharacter(cc7::U32 utf_codepoint, size_t index)
    {
        if (isMutable()) {
            if (index <= _char_pos->size()) {
                cc7::ByteArray bytes;
                bytes.reserve(4);
                if (CC7_CHECK(_UTF8Encode(utf_codepoint, bytes), "Wrong codepoint")) {
                    size_t offset = indexToPos(index);
                    // store actual position to the positions
                    _char_pos->insert(_char_pos->begin() + index, offset);
                    // Reveal bytes from offset to the end
                    inplaceXor(offset);
                    // insert bytes
                    _pass.insert(_pass.begin() + offset, bytes.begin(), bytes.end());
                    // Hide bytes from offset to the end
                    inplaceXor(offset);
                    // update positions after the inserted one
                    updateIndexes(index + 1, bytes.size());
                    return true;
                }
            }
        }
        return false;
    }
    
    bool Password::removeLastCharacter()
    {
        if (isMutable()) {
            if (length() > 0) {
                size_t offset = indexToPos(_char_pos->size() - 1);
                // remove bytes from the password
                _pass.erase(_pass.begin() + offset, _pass.end());
                // remove the position
                _char_pos->pop_back();
                return true;
            }
        }
        return false;
    }
    
    bool Password::removeCharacter(size_t index)
    {
        if (isMutable()) {
            if (index < _char_pos->size()) {
                size_t offset = indexToPos(index);
                size_t bytes  = indexToPos(index + 1) - offset;
                // decrypt all bytes from offset + bytes to the end
                inplaceXor(offset + bytes);
                // remove bytes from the password
                _pass.erase(_pass.begin() + offset, _pass.begin() + offset + bytes);
                // re-encrypt all bytes from offset to the end
                inplaceXor(offset);
                // remove the position
                _char_pos->erase(_char_pos->begin() + index);
                // update positions after the removed one
                updateIndexes(index, -bytes);
                return true;
            }
        }
        return false;
    }

    // MARK: - Private interface -

    size_t Password::indexToPos(size_t index)
    {
        if (index < _char_pos->size()) {
            return _char_pos->operator[](index);
        }
        return _pass.size();
    }
    
    void Password::updateIndexes(size_t begin, ptrdiff_t offset)
    {
        while (begin < _char_pos->size()) {
            _char_pos->operator[](begin) += offset;
            ++begin;
        }
    }

    // MARK: Password protection

    void Password::inplaceXor(size_t begin)
    {
        while (begin < _pass.size()) {
            _pass[begin] ^= _pass[begin % randomKeySize];
            ++begin;
        }
    }

} // io::getlime::powerAuth
} // io::getlime
} // io
