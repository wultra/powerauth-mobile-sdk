/*
 * Copyright 2017 Wultra s.r.o.
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
public class Password {
    
    //
    // Init & Destroy
    //
    static {
        System.loadLibrary("PowerAuth2Module");
    }
    
    /**
     * Pointer to native underlying object
     */
    private long handle;
    
    /**
     * Constructs a new instance of <b>immutable</b> Password object, initialized with UTF8 data
     * from the given string. The method is useful for scenarios, when you have
     * the full password already prepared and you want to pass it to the Session
     * as a parameter.
     *
     * @param passphrase string with password
     */
    public Password(String passphrase) {
        this.handle = this.initPassword(passphrase, null);
    }
    
    /**
     * Constructs a new instance of <b>immutable</b> Password object, initialized with the content
     * copied from given byte array. The password object will contain an immutable
     * passphrase, created exactly from the bytes, provided by the array.
     *
     * @param passphrase bytes with password
     */
    public Password(byte[] passphrase) {
        this.handle = this.initPassword(null, passphrase);
    }
    
    /**
     * Constructs a new instance of empty, <b>mutable</b> Password object.
     */
    public Password() {
        this.handle = this.initPassword(null, null);
    }
    
    /**
     * Initializes internal passphrase with given string or byte array based passphrase.
     * You cannot pass a both parameters at the same time, but both parameters can be
     * null. In this case, the mutable Password is initialized.
     *
     * @param strPass password in string representation
     * @param dataPass raw password bytes
     */
    private native long initPassword(String strPass, byte[] dataPass);
    
    
    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public synchronized void destroy() {
        if (this.handle != 0) {
            destroy(this.handle);
            this.handle = 0;
        }
    }
    
    /**
     * Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }
    
    /**
     * Internal JNI destroy. You have to provide handle created during the initialization.
     */
    private native void destroy(long handle);
    
    
    //
    // Methods for immutable operations
    //
    
    /**
     * @return true if {@code Password} object was created as mutable, or false if is immutable.
     */
    public native boolean isMutable();
    
    /**
     * @return If password is immutable, then returns length of password in bytes.
     *         If password is mutable, then returns a number of characters stored in the object.
     */
    public native int length();
    
    /**
     * Compares two passwords.
     *
     * @param anotherPassword object to compare
     *
     * @return true when this object and another password object contains equal passphrase.
     */
    public native boolean isEqualToPassword(Password anotherPassword);
    
    
    //
    // Mutable operations
    //
    
    /**
     * Clears internally stored passphrase.
     *
     * @return false if the object was initialized as immutable.
     */
    public native boolean clear();

    /**
     * Adds one unicode code point at the end of the passphrase.
     *
     * @param utfCodepoint unicode code point to add
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or code the point is invalid.
     */
    public native boolean addCharacter(int utfCodepoint);

    /**
     * Inserts unicode code point at the desired index.
     *
     * @param utfCodepoint unicode code point to add
     * @param index where the character has be inserted
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or code point is invalid, or index is out of the range.
     */
    public native boolean insertCharacter(int utfCodepoint, int index);

    /**
     * Removes last unicode code point from the passphrase.
     *
     * @return Returns true if operation succeeded or false if object is not
     *         mutable, or passphrase is already empty.
     */
    public native boolean removeLastCharacter();

    /**
     * Removes character from desired index.
     *
     * @param index index of character to be removed
     *
     * @return true if operation succeeded or false if object is not
     *         mutable, or index is out of the range.
     */
    public native boolean removeCharacter(int index);
}
