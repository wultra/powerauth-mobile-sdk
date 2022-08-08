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
        _pass.assign(data);
    }
    
    void Password::initAsMutable()
    {
        if (_char_pos) {
            _char_pos->clear();
        } else {
            _char_pos = new PosVector();
        }
        _pass.secureClear();
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
            return _pass.size();
        }
    }
    
    const cc7::ByteArray & Password::passwordData() const
    {
        return _pass;
    }
    
    bool Password::isEqualToPassword(const Password & p) const
    {
        return _pass == p.passwordData();
    }
    
    
    // MARK: - Mutable operations -
    
    bool Password::clear()
    {
        if (CC7_CHECK(isMutable(), "Object is immutable")) {
            initAsMutable();
            return true;
        }
        return false;
    }
    
    bool Password::addCharacter(cc7::U32 utf_codepoint)
    {
        if (CC7_CHECK(isMutable(), "Object is immutable")) {
            cc7::ByteArray bytes;
            bytes.reserve(4);
            if (CC7_CHECK(_UTF8Encode(utf_codepoint, bytes), "Wrong codepoint")) {
                // store current position (e.g. current size of pass)
                _char_pos->push_back(_pass.size());
                // append bytes...
                _pass.append(bytes);
                return true;
            }
        }
        return false;
    }
    
    bool Password::insertCharacter(cc7::U32 utf_codepoint, size_t index)
    {
        if (CC7_CHECK(isMutable(), "Object is immutable")) {
            if (CC7_CHECK(index <= _char_pos->size(), "Index is out of range")) {
                cc7::ByteArray bytes;
                bytes.reserve(4);
                if (CC7_CHECK(_UTF8Encode(utf_codepoint, bytes), "Wrong codepoint")) {
                    size_t offset = indexToPos(index);
                    // store actual position to the positions
                    _char_pos->insert(_char_pos->begin() + index, offset);
                    // insert bytes
                    _pass.insert(_pass.begin() + offset, bytes.begin(), bytes.end());
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
        if (CC7_CHECK(isMutable(), "Object is immutable")) {
            if (CC7_CHECK(length() > 0, "Password is already empty")) {
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
        if (CC7_CHECK(isMutable(), "Object is immutable")) {
            if (CC7_CHECK(index < _char_pos->size(), "Index is out of range")) {
                size_t offset = indexToPos(index);
                size_t bytes  = indexToPos(index + 1) - offset;
                // remove bytes from the password
                _pass.erase(_pass.begin() + offset, _pass.begin() + offset + bytes);
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


} // io::getlime::powerAuth
} // io::getlime
} // io
