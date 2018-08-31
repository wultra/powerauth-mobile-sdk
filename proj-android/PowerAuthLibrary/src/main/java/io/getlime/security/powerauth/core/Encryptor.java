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
 The Encryptor class provides an End-To-End Encryption between the client
 and the server. This class is used for both personalized and nonpersonalized
 E2EE modes of PA2 protocol.

 The direct instantiation of the object is not allowed but you can use the
 Session class for this purpose. You can use Session.createNonpersonalizedEncryptor()
 or Session.createPersonalizedEncryptor() methods depending on what kind of 
 encryptor you need.
 */
public class Encryptor {
    
    //
    // Init & Destroy
    //
    static {
        System.loadLibrary("PowerAuth2Module");
    }
    
    /**
     Pointer to native underlying object
     */
    private long handle;
    
    /**
     Contains error code from last executed operation. You can use
     this value for debug purposes. The returned integer can be compared
     against the constants available in the ErrorCode class.
     */   
    public final int lastErrorCode;
    
	/**
	 Internal JNI destroy. You have to provide handle created during the initialization.
	 */
	private native void destroy(long handle);
    
    /**
     Destroys underlying native C++ object. You can call this method
     if you want to be sure that internal C++ object is properly destroyed.
     You can't use instance of this java object anymore after this call.
     */
    public synchronized void destroy() {
        if (this.handle != 0) {
            destroy(this.handle);
            this.handle = 0;
        }
    }
    
    /**
     Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }
    
    /**
     Private constructor prevents class instantiation. The class is always instantiated 
     from the native code, so we don't need to expose any public constructor.
     */
    private Encryptor() {
        this.handle = 0;
        this.lastErrorCode = 0;
    }
    
    /**
     Returns current encryption mode. You can compare returned value against constants
     from the EncryptorMode class.
     */
    public native int encryptorMode();
    
    /**
     Returns session index used during the Encryptor object creation.
     */
    public native byte[] sessionIndex();
    
    /**
     Returns true if instance of this class contains valid C++ underlying Encryptor.
     You can use this method to validate whether the object returned from Session is valid or not.
     */
    public boolean isValid() {
        return this.handle != 0;
    }
    
    /**
     Encrypts a given bytes from |data| parameter and returns EncryptedMessage object
     with the result. The method fills appropriate properties of the message depending on the mode
     of encryption. For more details, check the EncryptedMessage documentation.

     Returns an EncryptedMessage object if succeeded or null in case of failure.
     The lastErrorCode property is updated to corresponding value. 
     */
    public native EncryptedMessage encrypt(byte[] data);
    
    /**
     Decrypts data from |message| and returns byte array with decrypted bytes.
     The EncryptedMessage object must contain all mandatory properties for current
     encryption mode. For more details, check the EncryptedMessage documentation.
 
     Returns a NSData object if succeeded or nil in case of failure.
     The lastErrorCode property is updated to corresponding value.
     */
    public native byte[] decrypt(EncryptedMessage message);
    
}