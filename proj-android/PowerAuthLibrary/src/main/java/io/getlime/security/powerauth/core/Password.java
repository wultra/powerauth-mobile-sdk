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

package io.getlime.security.powerauth.core;

import java.util.Arrays;

import androidx.annotation.NonNull;

/**
 * The {@code Password} is an object representing an arbitrary passphrase. The underlying implementation
 * guarantees that the sensitive information is cleared from the memory when the object is destroyed.
 *
 * <h2>Discussion</h2>
 * <p>
 * Working with an user's passphrases is always a very delicate task. The good implementation should
 * always follow several well known rules, for example:
 *
 * <ol>
 *   <li>Should minimize traces of the plaintext passphrase in the memory</li>
 *   <li>Should not allow serialization of sensitive information to the persistent storage</li>
 *   <li>Should keep the plaintext passphrase in memory as short as possible</li>
 * </ol>
 * <p>
 * Achieving all these principles together is usually very difficult, especially in managed
 * environments, like Java or Objective-C is. For exmaple, you can find a plenty of examples
 * in the past where the system keyboard leaked the passphrases, usually into the dynamic
 * dictionary used by keyboard's auto-complete feature.
 * <p>
 * Moreover, all these managed environments uses immutable strings for a string concatenation.
 * The result is that one simple user's passphrase is copied in hundred versions over the
 * whole process memory.
 * <p>
 * Due to this quirks, this PowerAuth library implementation provides its own custom objects
 * responsible for manipulation with passwords. You can use these objects in several, very
 * different scenarios, and its  only up to you which one you'll choose for your application:
 *
 * <h3>1. Wrapping an already complete passphrase</h3>
 * <p>
 * This is the simplest scenario, where you can simply create a Password object with a final
 * passphrase. You can use constructors with string or byte array parameters to do this.
 * In this situation, you typically leaving an entering the passphrase on the system components,
 * with all its advantages (easy to use) and disadvantages (usually not very secure).
 *
 * <h3>2. Using mutable PIN passphrase</h3>
 * <p>
 * If only the digits are allowed, then it's very recommended to create a custom UI interface
 * for a PIN keyboard and use the mutable Password object as the backing storage for
 * the passphrase.
 *
 * <h3>3. Using mutable alphanumeric passphrase</h3>
 * <p>
 * This approach is achievable, but usually very difficult to implement. Handling all the events
 * from the keyboard properly, is not an easy task, but the benefits are obvious.
 * At the end, you can get benefits from a supporting very strong passphrases and also
 * you'll minimize all traces of the passphrase in the memory.
 */
public class Password extends NativeObject {
    
    //
    // Init & Destroy
    //

    /**
     * Constructs a new instance of <b>immutable</b> Password object, initialized with UTF8 data
     * from the given string. The method is useful for scenarios, when you have
     * the full password already prepared and you want to pass it to the Session
     * as a parameter.
     *
     * @param passphrase string with password.
     */
    public Password(String passphrase) {
        this(initPassword(passphrase, null, NATIVE_NULL));
    }
    
    /**
     * Constructs a new instance of <b>immutable</b> Password object, initialized with the content
     * copied from given byte array. The password object will contain an immutable
     * passphrase, created exactly from the bytes, provided by the array.
     *
     * @param passphrase bytes with password
     */
    public Password(byte[] passphrase) {
       super(initPassword(null, passphrase, NATIVE_NULL));
    }
    
    /**
     * Constructs a new instance of empty, <b>mutable</b> Password object.
     */
    public Password() {
        super(initPassword(null, null, NATIVE_NULL));
    }

    /**
     * Construct a password with an already created handle pointing to a native object.
     * @param handle Handle, or 0, if the object is already destroyed.
     */
    private Password(long handle) {
        super(handle);
    }

    /**
     * Initializes internal passphrase with given string or byte array based passphrase.
     * You cannot pass a both parameters at the same time, but both parameters can be
     * null. In this case, the mutable Password is initialized.
     *
     * @param strPass password in string representation
     * @param dataPass raw password bytes
     * @param handleOtherPassword Handle of other password to copy.
     */
    private static native long initPassword(String strPass, byte[] dataPass, long handleOtherPassword) throws IllegalStateException;

    /**
     * Create an immutable copy from this Password. If the password object is already destroyed,
     * then the created copy is also marked as a destroyed.
     * @return Immutable
     */
    @NonNull
    public Password copyToImmutable() {
        return new Password(initPassword(null, null, nativeObjectHandle));
    }

    //
    // Methods for immutable operations
    //
    
    /**
     * @return true if {@code Password} object was created as mutable, or false if is immutable.
     */
    public native boolean isMutable() throws IllegalStateException;

    /**
     * @return If password is immutable, then returns length of password in bytes.
     *         If password is mutable, then returns a number of characters stored in the object.
     */
    public native int length() throws IllegalStateException;

    /**
     * Compares two passwords.
     *
     * @param anotherPassword object to compare
     *
     * @return true when this object and another password object contains equal passphrase.
     */
    public boolean isEqualToPassword(Password anotherPassword) {
        if (anotherPassword == null) {
            return false;
        }
        return isEqualToPassword(nativeObjectHandle, anotherPassword.nativeObjectHandle);
    }

    /**
     * Compare two underlying native Password objects identified by its handles.
     * @param thisHandle This object's handle.
     * @param anotherHandle Another object's handle.
     * @return true if both objects contains the same password.
     * @throws IllegalStateException In case handles are no longer valid.
     */
    private native static boolean isEqualToPassword(long thisHandle, long anotherHandle) throws IllegalStateException;

    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof Password) {
            return isEqualToPassword((Password) anObject);
        }
        return false;
    }
    
    //
    // Mutable operations
    //
    
    /**
     * Clears internally stored passphrase.
     *
     * @return false if the object was initialized as immutable.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    public native boolean clear() throws IllegalStateException;

    /**
     * Adds one unicode code point at the end of the passphrase.
     *
     * @param utfCodepoint unicode code point to add
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or code the point is invalid.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    public native boolean addCharacter(int utfCodepoint) throws IllegalStateException;

    /**
     * Inserts unicode code point at the desired index.
     *
     * @param utfCodepoint unicode code point to add
     * @param index where the character has be inserted
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or code point is invalid, or index is out of the range.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    public native boolean insertCharacter(int utfCodepoint, int index) throws IllegalStateException;

    /**
     * Removes last unicode code point from the passphrase.
     *
     * @return Returns true if operation succeeded or false if object is not
     *         mutable, or passphrase is already empty.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    public native boolean removeLastCharacter() throws IllegalStateException;

    /**
     * Removes character from desired index.
     *
     * @param index index of character to be removed
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or index is out of the range.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    public native boolean removeCharacter(int index) throws IllegalStateException;

    //
    // Password complexity validation
    //

    /**
     * Function provide password in the plaintext form. It's expected that function that acquire
     * plaintext password does safe content cleanup after the array is no longer needed.
     *
     * @return Array of bytes with plaintext password.
     * @throws IllegalStateException In case native handle is no longer valid.
     */
    private native static byte[] getPlaintextPassword(long handle) throws IllegalStateException;

    /**
     * The {@code IPasswordComplexityValidator} provides simple interface to validate password
     * complexity.
     */
    public interface IPasswordComplexityValidator {
        /**
         * Method is called from {@link Password#validatePasswordComplexity(IPasswordComplexityValidator)}
         * function to determine the complexity of the stored password. The PowerAuth SDK doesn't provide
         * such functionality, so it's up to your application to implement the actual validation.
         *
         * @param passwordBytes Array of bytes with plaintext password. It's not recommended to copy
         *                      the plaintext password to another array or to the String, to minimize
         *                      traces of the password in the memory.
         * @return Value representing a complexity of password. The actual meaning is up to the provided
         * implementation.
         */
        int validatePasswordComplexity(@NonNull byte[] passwordBytes);
    }

    /**
     * Validate complexity of stored password. The function
     * @param complexityValidator Object that implement password complexity validation.
     * @return Value returned from the complexity validation.
     * @throws IllegalStateException in case that underlying C++ object is already destroyed.
     */
    public int validatePasswordComplexity(@NonNull IPasswordComplexityValidator complexityValidator) throws IllegalStateException {
        final byte[] passwordBytes = getPlaintextPassword(nativeObjectHandle);
        final int result = complexityValidator.validatePasswordComplexity(passwordBytes);
        // cleanup array of bytes
        Arrays.fill(passwordBytes, (byte) 0);
        return result;
    }
}
