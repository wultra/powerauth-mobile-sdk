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

import android.util.Pair;

import io.getlime.security.powerauth.ecies.EciesMetadata;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 *  The <code>EciesEncryptor</code> class implements a request encryption and response decryption for
 *  our custom ECIES scheme. For more details about our ECIES implementation, please check documentation
 *  available at the beginning of <code>&lt;PowerAuth/ECIES.h&gt;</code> C++ header.
 */
public class EciesEncryptor {

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
     * Service providing time synchronized with the server.
     */
    private final ICoreTimeService timeService;

    /**
     * Constructs a new encryptor with public key and optional shared info2 parameter.
     * @param publicKey EC public key in Base64 format
     * @param sharedInfo1 An optional shared info 1 data
     * @param sharedInfo2 An optional shared info 2 data
     * @param timeService Time providing service.
     */
    public EciesEncryptor(String publicKey, byte[] sharedInfo1, byte[] sharedInfo2, ICoreTimeService timeService) {
        this.handle = init(publicKey, sharedInfo1, sharedInfo2);
        this.timeService = timeService;
    }


    /**
     * Returns a new instance of {@code EciesEncryptor}, suitable only for data decryption or null
     * if current encryptor is not able to decrypt response (this happens typically if you did not
     * call `encryptRequest` or instance contains invalid keys).
     *
     * <h2>Discussion</h2>
     *
     * The returned copy will not be able to encrypt a new requests, but will be able to decrypt
     * a received response. This behavior is helpful when processing of simultaneous encrypted
     * requests and responses is required. Due to fact, that our ECIES scheme is generating
     * an unique key for each request-response round trip, you need to capture that key for later
     * safe decryption. As you can see, that might be problematic, because you don't know when
     * exactly the response will be received. To help with this, you can make a copy of the object
     * and use that copy only for response decryption.
     * <p>
     * The <code>encryptRequestSynchronized</code> method is an one example of safe approach, but
     * you can implement your own processing, if the thread safety is not a problem.
     *
     * @return New instance of {@code EciesEncryptor} suitable for data decryption or null in case of error
     *         or if this encryptor can't decrypt data.
     */
    public EciesEncryptor copyForDecryption() {
        long handleCopy = this.copyHandleForDecryption();
        if (handleCopy != 0) {
            return new EciesEncryptor(handleCopy, timeService);
        }
        return null;
    }

    /**
     * Constructs a new encryptor with specific handle. This constructor is private and is used
     * internally by this class.
     *
     * @param handle A handle representing underlying native C++ object
     */
    private EciesEncryptor(long handle, ICoreTimeService timeService) {
        this.handle = handle;
        this.timeService = timeService;
    }

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
     Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }

    /**
     * Internal JNI destroy.
     *
     * @param handle A handle representing underlying native C++ object
     */
    private native void destroy(long handle);

    /**
     * Internal JNI initialization.
     *
     * @param publicKey EC public key in Base64 format
     * @param sharedInfo1 An optional shared info 1 bytes
     * @param sharedInfo2 An optional shared info 2 bytes
     * @return A handle representing underlying native C++ object
     */
    private native long init(String publicKey, byte[] sharedInfo1, byte[] sharedInfo2);

    /**
     * Internal JNI copy.
     *
     * @return A handle representing new underlying native C++ object. If returned value is equal
     *         to zero, then this instance cannot be used for response decryption.
     */
    private native long copyHandleForDecryption();

    //
    // Getters
    //

    /**
     * @return EC public key in Base64 format
     */
    public native String getPublicKey();

    /**
     * @return nullable byte array with shared info1 parameter.
     */
    public native byte[] getSharedInfo1();

    /**
     * @return nullable byte array with shared info2 parameter.
     */
    public native byte[] getSharedInfo2();


    /**
     * @return true if this instance can be used for request encryption.
     */
    public native boolean canEncryptRequest();

    /**
     * @return true if this instance can be used for response decryption.
     */
    public native boolean canDecryptResponse();

    //
    // Encrypt & Decrypt
    //


    /**
     * Encrypts an input request data into <code>EciesCryptogram</code> object or null in case of
     * failure.
     *
     * <h2>Discussion</h2>
     *
     * Be aware that each call for this method will regenerate an internal envelope key, so you
     * should use the method only in pair with subsequent call to <code>decryptResponse</code>.
     * If you plan to reuse one encryptor for multiple simultaneous requests, then you should make
     * a copy of the object after every successful encryption.
     * <p>
     * Check <code>copyForDecryption</code> or  <code>encryptRequestSynchronized</code> methods
     * for details.
     *
     * @param requestData data to be encrypted
     * @return cryptogram object or null in case of failure
     */
    public EciesCryptogram encryptRequest(byte[] requestData) {
        if (!timeService.isTimeSynchronized()) {
            PowerAuthLog.w("Time service is not synchronized. Encrypted data may be rejected on the server.");
        }
        timeSynchronizationTask = timeService.startTimeSynchronizationTask();
        return encryptRequestImpl(requestData, timeService.getCurrentTime());
    }

    private native EciesCryptogram encryptRequestImpl(byte[] requestData, long timestamp);


    /**
     * Encrypts an input request data into pair with future decryptor and cryptogram.
     *
     * <h2>Discussion</h2>
     *
     * This is a special, thread-safe version of request encryption. The method encrypts provided
     * data and makes a copy of itself in thread synchronized zone. Then the pair of objects
     * is returned. The pair is composed of cryptogram and copied encryptor's instance, which is
     * suitable only for response decryption.
     * <p>
     * Note that the rest of the encryptor's interface is not thread safe. So, once the shared
     * instance for encryption is created, then you should not change its parameters or call other
     * not-synchronized methods.
     *
     * @param requestData data to be encrypted
     * @return pair with decryptor and cryptogram, or null in case of failure.
     */
    public synchronized Pair<EciesEncryptor, EciesCryptogram> encryptRequestSynchronized(byte[] requestData) {
        EciesCryptogram cryptogram = this.encryptRequest(requestData);
        if (cryptogram != null) {
            EciesEncryptor decryptor = this.copyForDecryption();
            if (decryptor != null) {
                decryptor.setMetadata(this.metadata);
                decryptor.timeSynchronizationTask = timeSynchronizationTask;
                timeSynchronizationTask = null;
                return new Pair<>(decryptor, cryptogram);
            }
        }
        return null;
    }

    /**
     * Decrypts a cryptogram received from the server and returns decrypted data or null in case
     * of failure.
     *
     * @param cryptogram cryptogram received from the server
     * @return decrypted bytes or null in case of error
     */
    public byte[] decryptResponse(EciesCryptogram cryptogram) {
        final byte[] result = decryptResponseImpl(cryptogram);
        if (result != null) {
            if (timeSynchronizationTask != null) {
                timeService.completeTimeSynchronizationTask(timeSynchronizationTask, cryptogram.timestamp);
            }
        }
        timeSynchronizationTask = null;
        return result;
    }

    private native byte[] decryptResponseImpl(EciesCryptogram cryptogram);

    //
    // Time synchronization task
    //
    private Object timeSynchronizationTask;


    //
    // Metadata
    //

    /**
     * Data associated to this encryptor.
     */
    private EciesMetadata metadata;

    /**
     * Sets metadata object to this encryptor. Note that the metadata object is not required
     * for data encryption or decryption, but it's typically useful for request &amp; response
     * processing.
     *
     * @param metadata object associated with this encryptor
     */
    public void setMetadata(EciesMetadata metadata) {
        this.metadata = metadata;
    }


    /**
     * @return metadata object associated to this encryptor.
     */
    public EciesMetadata getMetadata() {
        return metadata;
    }
}
