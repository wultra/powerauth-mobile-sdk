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
 The EncryptedMessage class represents an encrypted data transmitted 
 between the client and the server. The object is mostly used as a parameter in
 interface, provided by Encryptor class.
 
 The message is used in both ways, for the request encryption and also for 
 response decryption. Note that some members of the class are optional
 or depends on the mode of E2EE or the direction of communication.
 
 For more details check the online documentation about End-To-End Encryption.
 */
public class EncryptedMessage {

    /**
     Contains applicationKey copied from the Session which constructed the Encryptor
     object. The value is valid only for non-personalized encryption and is
     validated in responses, received from the server.
     */
    public final String applicationKey;
    /**
     Contains activationId copied  from the Session which constructed the Encryptor
     object. The value is valid only for personalized encryption and is validated
     in responses, received from the server.
     */
    public final String activationId;
    /**
     Data encrypted in the Encryptor or decrypted by the class when received
     a response from the server.
     */
    public final String encryptedData;
    /**
     Encrypted data signature.
     */
    public final String mac;
    /**
     Key index specific for one particular Encryptor. The value is validated for
     responses received from the server.

     Note that the term "session" is different than the Session used in this PA2 
     implementation. The "sessionIndex" in this case is a constant representing
     an estabilished session between client and the server. It's up to application
     to acquire and manage the value. Check the PA2 online documentation for details.
     */
    public final String sessionIndex;
    /**
     Key index used for one request or response. The value is calculated by
     the Encryptor during the encryption and required in decryption operation.
     */
    public final String adHocIndex;
    /**
     Key index used for one request or response. The value is calculated by
     the Encryptor during the encryption and required in decryption operation.
     */
    public final String macIndex;
    /**
     Nonce value used as IV for encryption. The value is calculated by
     the Encryptor during the encryption and required in decryption operation.
     */
    public final String nonce;
    /**
     A key used for deriving temporary secret. The value is provided by 
     the Encryptor class during the encryption operation, but only if the 
     nonpersonalized mode is in use.
     */
    public final String ephemeralPublicKey;

    /**
     Constructs EncryptedMessage with given parameters.
     */
    public EncryptedMessage(String applicationKey, 
                            String activationId,
                            String encryptedData,
                            String mac,
                            String sessionIndex,
                            String adHocIndex,
                            String macIndex,
                            String nonce,
                            String ephemeralPublicKey) {
        this.applicationKey = applicationKey;
        this.activationId = activationId;
        this.encryptedData = encryptedData;
        this.mac = mac;
        this.sessionIndex = sessionIndex;
        this.adHocIndex = adHocIndex;
        this.macIndex = macIndex;
        this.nonce = nonce;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
    
    /**
     Constructs empty EncryptedMessage. This constructor is used in the native
     code during the decryption process.
     */
    public EncryptedMessage() {
        this.applicationKey = null;
        this.activationId = null;
        this.encryptedData = null;
        this.mac = null;
        this.sessionIndex = null;
        this.adHocIndex = null;
        this.macIndex = null;
        this.nonce = null;
        this.ephemeralPublicKey = null;
    }
}