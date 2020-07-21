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

package io.getlime.security.powerauth.keychain;

/**
 * Thrown to indicate that you have accessed a different value type than
 * is stored in Keychain.
 */
public class IllegalKeychainAccessException extends RuntimeException {
    /**
     * Constructs an {@code IllegalKeychainAccessException} with no
     * detail message.
     */
    public IllegalKeychainAccessException() {
        super();
    }

    /**
     * Constructs an {@code IllegalKeychainAccessException} with the
     * specified detail message.
     *
     * @param message the detail message.
     */
    public IllegalKeychainAccessException(String message) {
        super(message);
    }

    /**
     * Constructs {@code IllegalKeychainAccessException} with the specified
     * detail message and cause.
     * <p>
     * Note that the detail message associated with {@code cause} is
     * not automatically incorporated in this exception's detail message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link Throwable#getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link Throwable#getCause()} method).  (A {@code null} value
     *                is permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     */
    public IllegalKeychainAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
