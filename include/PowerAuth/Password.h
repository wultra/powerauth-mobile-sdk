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
#include <cc7/BaseObject.h>

namespace powerAuth {

/// The Password class implements simple class for wrapping and manipulating
/// with an user's password.
///
/// Note that unlike the high level interfaces, this low level C++ implementation
/// supports both mutable and immutable passwords. The immutability depends only
/// on how the object was initialized for the last time.
class Password : public  cc7::BaseObject
{
public:
    
    // MARK: - Construction, Destruction -

    /// Constructs a new empty, immutable password.
    Password() noexcept;
    
    /// Constructs a new immutable password with password data.
    /// - Parameter data: Password data.
    Password(const cc7::ByteRange & data) noexcept;
    
    /// Initializes object for immutable password data.
    /// The existing password is replaced with content of data.
    /// - Parameter data: New password data.
    void initAsImmutable(const cc7::ByteRange & data) noexcept;
    
    /// Initializes object for mutable password. The existing password
    /// is removed.
    void initAsMutable() noexcept;
    
    
    // MARK: - Immutable operations -
    
    /// Returns `true` if password was initialized as mutable.
    bool isMutable() const noexcept;

    
    /// If password is immutable, then returns length of password in bytes.
    /// If password is mutable, then returns number of characters stored in the password.
    size_t length() const noexcept;

    /// Returns copy of plaintext password data.
    cc7::ByteArray passwordData() const noexcept;
    
    /// Returns `true` when both objects contains equal password.
    /// - Parameter p: Another password
    /// - Returns: `true` if both passwords are equal.
    bool isEqualToPassword(const Password & p) const noexcept;

    /// Convert this object into ByteArray with plaintext password.
    operator cc7::ByteArray () const noexcept;
    
    // MARK: - Mutable operations -

    /// Clears content of password.
    /// - Returns: `false` only if the object was initialized as immutable.
    bool clear() noexcept;

    /// Adds one unicode code point at the end of password.
    ///
    /// - Parameter utf_codepoint: UTF code point
    /// - Returns: `true` if operation succeeded or `false` if object is not
    ///   mutable, or code point is invalid.
    bool addCharacter(cc7::U32 utf_codepoint) noexcept;

    /// Inserts unicode code point at the desired index.
    ///
    /// - Parameters:
    ///   - utf_codepoint: Unicode code point.
    ///   - index: Index where code point should be inserted.
    /// - Returns: `true` if operation succeeded or `false` if object is not
    ///   mutable, or code point is invalid, or index is out of the range.
    bool insertCharacter(cc7::U32 utf_codepoint, size_t index) noexcept;

    
    /// Removes last unicode code point from the password.
    /// Returns true if operation succeeded or false if object is not
    /// mutable, or password is already empty.
    /// - Returns: `true` if operation succeeded or `false` if object is not
    ///   mutable, or code point is invalid, or index is out of the range.
    bool removeLastCharacter() noexcept;

    
    /// Removes character from desired index. Returns true if operation succeeded or false if object is not
    /// mutable, or index is out of the range.
    /// - Parameter index: Index of character to being removed.
    /// - Returns: `true` if operation succeeded or `false` if object is not mutable, or index
    ///   is out of the range.
    bool removeCharacter(size_t index) noexcept;

    
    /// Clear stored password securely. Unlike clear(), this method
    /// also clears content of immutable Password. In this case, the result
    /// is immutable empty password.
    void secureClear() noexcept;
    
private:
    
    // MARK: - Private section -
    
    typedef std::vector<size_t> PosVector;

    /// Buffer with password, where first `randomKeySize` bytes represents
    /// a key for simple XOR cipher. The rest of the `_pass` array contains
    /// actual password XOR'ed with the key. See `inplaceXor()`
    /// function for more details.
    cc7::ByteArray  _pass;

    /// Character positions, valid only for mutable instances.
    std::unique_ptr<PosVector> _char_pos;

    /// In mutable object, converts character index into position to
    /// `_pass` array.
    size_t indexToPos(size_t index) noexcept;

    
    /// Updates all offsets in `_char_pos` array, from begin index
    /// to the end of the vector.
    ///
    /// - Parameters:
    ///   - begin: Offset where update starts.
    ///   - offset: Difference applied to all offsets in update range.
    void updateIndexes(size_t begin, ptrdiff_t offset) noexcept;
    
    // MARK: Password protection

    /// Size of key for XOR function.
    const size_t randomKeySize = 16;

    /// Modify `_pass` buffer from begin position to the end of the buffer,
    /// by xoring with appropriate value from range `<0, randomKeySize)`.
    void inplaceXor(size_t begin) noexcept;
};

CC7_SHARED_PTR(Password)

} // namespace powerAuth
