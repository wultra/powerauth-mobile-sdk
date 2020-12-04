/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.keychain.impl;

import androidx.annotation.NonNull;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import io.getlime.security.powerauth.keychain.IllegalKeychainAccessException;

/**
 * The {@code KeychainValueEncoder} serializes various Java types into sequence of bytes and vice
 * versa. The first byte in encoded sequence always contains an additional information about the
 * encoded value type, so it's later safe to decode such value into the requested value type.
 */
class KeychainValueEncoder {

    /**
     * Constant for plain data encoded in keychain.
     */
    private static final byte TYPE_DATA = 1;
    /**
     * Constant for string encoded in keychain.
     */
    private static final byte TYPE_STRING = 2;
    /**
     * Constant for long value encoded in keychain.
     */
    private static final byte TYPE_BOOLEAN = 3;
    /**
     * Constant for long value encoded in keychain.
     */
    private static final byte TYPE_LONG = 4;
    /**
     * Constant for float value encoded in keychain.
     */
    private static final byte TYPE_FLOAT = 5;
    /**
     * Constant for set of strings encoded in keychain.
     */
    private static final byte TYPE_STRING_SET = 6;


    // Encode to bytes

    /**
     * Encode array of bytes into format that preserve the type.
     *
     * @param value Array of bytes to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(@NonNull byte[] value) {
        final byte[] encoded = new byte[1 + value.length];
        encoded[0] = TYPE_DATA;
        System.arraycopy(value, 0, encoded, 1, value.length);
        return encoded;
    }

    /**
     * Encode {@code String} into sequence of bytes that preserve the encoded value type.
     *
     * @param value {@code String} value to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(@NonNull String value) {
        final byte[] encodedString = value.getBytes(Charset.defaultCharset());
        final byte[] encoded = new byte[1 + encodedString.length];
        encoded[0] = TYPE_STRING;
        System.arraycopy(encodedString, 0, encoded, 1, encodedString.length);
        return encoded;
    }

    /**
     * Encode {@code boolean} value into sequence of bytes that preserve the encoded value type.
     *
     * @param value {@code boolean} value to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(boolean value) {
        final byte[] encoded = new byte[2];
        encoded[0] = TYPE_BOOLEAN;
        encoded[1] = value ? (byte)1 : (byte)0;
        return encoded;
    }

    /**
     * Encode {@code long} value into sequence of bytes that preserve the encoded value type.
     *
     * @param value {@code long} value to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(long value) {
        final ByteBuffer buffer = ByteBuffer.allocate(1 + 8);
        buffer.put(TYPE_LONG);
        buffer.putLong(value);
        return buffer.array();
    }

    /**
     * Encode {@code float} value into sequence of bytes that preserve the encoded value type.
     *
     * @param value {@code float} value to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(float value) {
        final ByteBuffer buffer = ByteBuffer.allocate(1 + 4);
        buffer.put(TYPE_FLOAT);
        buffer.putFloat(value);
        return buffer.array();
    }

    /**
     * Encode set of strings into sequence of bytes that preserve the encoded value type.
     *
     * @param strings Set of strings to encode.
     * @return Encoded array of bytes.
     */
    @NonNull byte[] encode(@NonNull Set<String> strings) {
        final int count = strings.size();
        // Convert all strings into bytes and estimate the total bytes required for all strings.
        List<byte[]> encodedStrings = new ArrayList<>(count);
        int stringsLength = 0;
        for (String string : strings) {
            byte[] encodedString = string.getBytes(Charset.defaultCharset());
            encodedStrings.add(encodedString);
            stringsLength += encodedString.length;
        }
        // Total length counts with:
        // - type marker (1 byte)
        // - count (4 bytes)
        // - count * 4 bytes (for per string lengths)
        // - all encoded strings content.
        int totalLength = 1 + 4 + 4 * count + stringsLength;
        // Encode content
        final ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.put(TYPE_STRING_SET);
        buffer.putInt(count);
        for (int index = 0; index < count; index++) {
            final byte[] encodedString = encodedStrings.get(index);
            final int encodedStringLength = encodedString.length;
            buffer.putInt(encodedStringLength);
            buffer.put(encodedString);
        }
        return buffer.array();
    }


    // Decode from bytes

    /**
     * Decode array of bytes from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value.
     *
     * @param encoded Sequence of bytes containing encoded {@code String} value.
     * @return Decoded {@code String} value.
     */
    @NonNull byte[] decodeBytes(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_DATA);
        return Arrays.copyOfRange(encoded, 1, encoded.length);
    }

    /**
     * Decode {@code String} value from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value.
     *
     * @param encoded Sequence of bytes containing encoded {@code String} value.
     * @return Decoded {@code String} value.
     */
    @NonNull String decodeString(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_STRING);
        return new String(encoded, 1, encoded.length - 1, Charset.defaultCharset());
    }

    /**
     * Decode {@code boolean} value from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value, or there's not
     * enough bytes to decode the value.
     *
     * @param encoded Sequence of bytes containing encoded {@code boolean} value.
     * @return Decoded {@code boolean} value.
     */
    boolean decodeBoolean(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_BOOLEAN);
        return encoded[1] != 0;
    }

    /**
     * Decode {@code long} value from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value, or there's not
     * enough bytes to decode the value.
     *
     * @param encoded Sequence of bytes containing encoded {@code long} value.
     * @return Decoded {@code long} value.
     */
    long decodeLong(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_LONG);
        return ByteBuffer.wrap(encoded,1, 8).getLong();
    }

    /**
     * Decode {@code float} value from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value, or there's not
     * enough bytes to decode the value.
     *
     * @param encoded Sequence of bytes containing encoded {@code float} value.
     * @return Decoded {@code float} value.
     */
    float decodeFloat(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_FLOAT);
        return ByteBuffer.wrap(encoded, 1, 4).getFloat();
    }

    /**
     * Decode {@code Set<String>} from encoded sequence of bytes. The {@link IllegalKeychainAccessException}
     * is thrown in case that encoded sequence contains a different type of value, or there's not
     * enough bytes to decode the value.
     *
     * @param encoded Sequence of bytes containing encoded {@code Set<String>}.
     * @return Decoded {@code Set<String>}.
     */
    @NonNull Set<String> decodeStringSet(@NonNull byte[] encoded) {
        checkEncodedType(encoded, TYPE_STRING_SET);
        try {
            final ByteBuffer buffer = ByteBuffer.wrap(encoded, 1, encoded.length - 1);
            final int count = buffer.getInt();
            final Set<String> stringSet = new HashSet<>(count);
            for (int index = 0; index < count; index++) {
                final int encodedLength = buffer.getInt();
                final byte[] encodedString = new byte[encodedLength];
                buffer.get(encodedString);
                stringSet.add(new String(encodedString, Charset.defaultCharset()));
            }
            return stringSet;
        } catch (BufferUnderflowException e) {
            throw new IllegalKeychainAccessException("Not enough bytes for Set<String> value", e);
        }
    }


    // Private methods

    /**
     * Test whether encoded value's type is equal to expected type. The method also check whether encoded
     * sequence of bytes contains enough bytes to decode such value. The {@link IllegalKeychainAccessException}
     * is thrown in case that the expected type is different, or there's not enough bytes to decode the value.
     *
     * @param encoded Encoded keychain value.
     * @param expected Expected value type.
     */
    private void checkEncodedType(@NonNull byte[] encoded, byte expected) {
        if (encoded.length == 0) {
            throw new IllegalKeychainAccessException("Invalid encoded keychain content");
        }
        if (encoded[0] != expected) {
            throw new IllegalKeychainAccessException("Requesting '" + typeToString(expected) + "' but keychain contains '" + typeToString(encoded[0]) + "' type");
        }
        switch (expected) {
            case TYPE_DATA:
            case TYPE_STRING:
                // DATA and STRING can be always decoded with a zero length.
                return;
            case TYPE_BOOLEAN:
                if (encoded.length != 2) {
                    throw new IllegalKeychainAccessException("Not enough bytes for Boolean value");
                }
                return;
            case TYPE_LONG:
                if (encoded.length != 9) {
                    throw new IllegalKeychainAccessException("Not enough bytes for Long value");
                }
                return;
            case TYPE_FLOAT:
                if (encoded.length != 5) {
                    throw new IllegalKeychainAccessException("Not enough bytes for Float value");
                }
                return;
            case TYPE_STRING_SET:
                if (encoded.length < 5) {
                    throw new IllegalKeychainAccessException("Not enough bytes for Set<String> value");
                }
            default:
        }
    }

    /**
     * Convert encoded type constant into string.
     *
     * @param encodedType Type of encoded value.
     * @return String representation of encoded type.
     */
    private @NonNull String typeToString(byte encodedType) {
        switch (encodedType) {
            case TYPE_DATA:
                return "byte[]";
            case TYPE_STRING:
                return "String";
            case TYPE_BOOLEAN:
                return "Boolean";
            case TYPE_LONG:
                return "Long";
            case TYPE_FLOAT:
                return "Float";
            case TYPE_STRING_SET:
                return "Set<String>";
            default:
                return "Unknown";
        }
    }
}
