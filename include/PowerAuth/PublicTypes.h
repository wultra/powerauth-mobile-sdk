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

namespace io
{
namespace getlime
{
namespace powerAuth
{
    //
    // MARK: - Setup & Error code -
    //

    /**
     The SessionSetup structure defines unique constants required during the lifetime
     of the Session class.
     */
    struct SessionSetup
    {
        /**
         Defines APPLICATION_KEY for the session.
         */
        std::string applicationKey;
        
        /**
         Defines APPLICATION_SECRET for the module.
         */
        std::string applicationSecret;
        
        /**
         The master server public key, in BASE64 format.
         It's strongly recommended to use different keys for the testing
         and production servers.
         */
        std::string masterServerPublicKey;
        
        /**
         Optional external encryption key. If the array contains 16 bytes,
         then the key is considered as valid and will be used during the
         cryptographic operations.
         
         The additional encryption key is useful in  multibanking applications, where it allows the
         application to create chain of trusted PA2 activations. If the key is set, then the session will
         perform additional encryption / decryption operations when the signature keys are being used.
         
         The session implements a couple of simple protections against misuse of this feature and therefore
         once the session is activated with the EEK, then you have to use that EEK for all future cryptographic
         operations. The key is NOT serialized in the session's state and thus it's up to the application,
         how it manages the chain of multiple PA2 sessions.
         */
        cc7::ByteArray externalEncryptionKey;
        
        /**
         Constructs a new empty setup structure.
         */
        SessionSetup()
        {
        }
        
        /**
         Fill basic parameters to SessionSetup structure from provided Base64 string.
         */
        bool loadFromConfiguration(const std::string & config);
    };
    
    /**
     The ErrorCode enumeration defines all possible error codes
     produced by Session class. You normally need to check only
     if operation ended with EC_Ok or not. All other codes are
     only hints and should be used only for debugging purposes.
     
     For example, if the operation fails at EC_WrongState or EC_WrongParam,
     then it's usualy your fault and you're using session in wrong way.
     */
    enum ErrorCode
    {
        /**
         Everything is OK.
         You can go out with your friends and enjoy the beer or two :)
         */
        EC_Ok = 0,
        /**
         The method failed on an encryption. Whatever that means it's
         usually very wrong and the UI response depends on what
         method did you call. Typically, you have to perform retry
         or restart for the whole process.
         
         This error code is also returned when decoding of important
         parameter failed. For example, if BASE64 encoded value
         is in wrong format, then this is considered as an attack
         attempt.
         */
        EC_Encryption,
        /**
         You have called method in wrong session's state. Usually that
         means that you're using session in a  wrong way. This kind
         of error should not be propagated to the UI. It's your
         responsibility to handle session states correctly.
         */
        EC_WrongState,
        /**
         You have called method with wrong or missing parameters.
         Usually this error code means that you're using session
         in wrong way and you did not provide all required data.
         This kind of error should not be propagated to UI. It's
         your responsibility to handle all user's inputs
         and validate all responses from server before you
         ask session for processing.
         */
        EC_WrongParam,
    };
    
    /**
     The Version enum defines PowerAuth protocol version. The main difference
     between V2 & V3 is that V3 is using hash-based counter instead of linear one,
     and all E2EE tasks are now implemented by ECIES.
     
     This version of SDK is supporting V2 protol in very limited scope, where only
     the V2 signature calculations are supported.
     */
    enum Version
    {
        /// Constant defining that version is not available. The enumeration
        /// has meaning in several APIs, where unknown or "no version"
        /// state can be returned as a regular result.
        Version_NA = 0,
        /// Constant defining Protocol Version 2.
        Version_V2 = 2,
        /// Constant defining Protocol Version 3.
        Version_V3 = 3,
        
        // Special constant for "latest" version
        Version_Latest = Version_V3
    };
    
    //
    // MARK: - Signatures -
    //
    
    /**
     The SignatureFactor constants defines factors involved in the signature
     computation. The factor types are tightly coupled with SignatureUnlockKeys
     structure.
     */
    typedef int SignatureFactor;
    /**
     The possession factor, you have to provide possessionUnlocKey.
     */
    const SignatureFactor SF_Possession     = 0x0001;
    /**
     The knowledge factor, you have to provide userPassword
     */
    const SignatureFactor SF_Knowledge      = 0x0010;
    /**
     The biometry factor, you have to provide biometryUnlockKey.
     */
    const SignatureFactor SF_Biometry       = 0x0100;
    /**
     2FA, with using possession and knowledge factors.
     */
    const SignatureFactor SF_Possession_Knowledge           = SF_Possession | SF_Knowledge;
    /**
     2FA, with using possession and biometric factors.
     */
    const SignatureFactor SF_Possession_Biometry            = SF_Possession | SF_Biometry;
    /**
     3FA, with using all supported factors.
     */
    const SignatureFactor SF_Possession_Knowledge_Biometry  = SF_Possession | SF_Knowledge | SF_Biometry;
    
    /**
     The SignatureUnlockKeys object contains all keys, required for signature computation.
     You have to provide all keys involved into the signature computation, for selected combination
     of factors. For example, if you're going to compute signature for Possession + Biometry
     factor, then this object must contain valid possessionUnlockKey and biometryUnlockKey.
     
     Discussion
     
     Internally, the Session keeps keys for signature computation always encrypted
     and doesn't expose these from outside of the class. This very strict approach is
     a prevention against accidental sensitive information leakage. Your application has
     control only over the keys, which actually encrypts and decrypts this sensitive information.
     
     At first read, it looks like that this additional protection layer has no cryptographic
     benefit at all. Yes, this is basically true :) The purpose of this layer is just to simplify
     the Session's interface. In this approach, the exact state of the session is always fully
     serializable and the only application's responsibility is to provide the lock / unlock keys
     in the right time, when these are really required.
     
     But still, you need to take care about how you're working
     with these unlock keys.
     */
    struct SignatureUnlockKeys
    {
        /**
         The key required for signatures with "possession" factor.
         You have to provide a key based on the unique properties of the device.
         For example, WI-FI MAC address or UDID are a good sources for this
         key. You can use Session::normalizeSignatureUnlockKeyFromData method
         to convert arbitrary data into normalized key.
         
         It is recommended to calculate this key for once, when the application starts
         and store in the volatile memory. You should never save this key to the
         permanent storage, like file system or keychain.
         
         You cannot use data object filled with zeros as a key.
         */
        cc7::ByteArray possessionUnlockKey;
        /**
         The key required for signatures with "biometry" factor. You should not
         use this key and factor, if device has no biometric engine available.
         You can use Session::generateSignatureUnlockKey for new key creation.
         
         You should store this key only to the storage, which can protect the
         key with using the biometry engine. For example, on iOS9+, you can use
         a keychain record, created with kSecAccessControlTouchID* flags.
         
         You cannot use data object filled with zeros as a key.
         */
        cc7::ByteArray biometryUnlockKey;
        /**
         The password required for signatures with "knowledge" factor. The complexity
         of the password depends on the rules, defined by the application. You should
         never store the password to the permanent storage (like file system, or keychain)
         
         The Session validates only the minimum lenght of the password (check private
         Constants.h and MINIMAL_PASSWORD_LENGTH constant for details)
         */
        cc7::ByteArray userPassword;
    };
    
    
    /**
     The HTTPRequestData structure contains all data required for calculating signature
     from HTTP request. You have to provide values at least non-empty strings to `method`
     and `uri` members, to pass a data validation.
     */
    struct HTTPRequestData
    {
        /**
         A whole POST body or data blob prepared in 'Session::prepareKeyValueMapForDataSigning'
         method. You can also calculate signature for an empty request with no body or without
         any GET parameters. In this case the member may be empty.
         */
        cc7::ByteArray body;
        /**
         HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected)
         */
        std::string method;
        /**
         Relative URI of the request.
         */
        std::string uri;
        /**
         Optional, contains NONCE generated externally. The value should be used for offline
         data signing purposes only. The Base64 string is expected.
         */
        std::string offlineNonce;
        /**
         Length of offline signature component. The default value is 8.
         */
        size_t offlineSignatureLength;
        
        /**
         Constructs an empty HTTPRequestData structure.
         */
        HTTPRequestData();
        
        /**
         Constructs a HTTPRequestData structure with provided |body|, |method|
         and |uri| parameters. The optional `offlineNonce` member will be empty.
         */
        HTTPRequestData(const cc7::ByteRange & body,
                        const std::string & method,
                        const std::string & uri);
        
        /**
         Constructs a HTTPRequestData structure with provided |body|, |method|, |uri|,
         |offlineNonce| and |offlineLength| parameters.
         */
        HTTPRequestData(const cc7::ByteRange & body,
                        const std::string & method,
                        const std::string & uri,
                        const std::string & offlineNonce,
                        size_t offlineLength);
        
        /**
         Returns true when structure contains valid data.
         */
        bool hasValidData() const;
        
        /**
         Returns true when this signature calculation request is for offline
         signatuere. This is exclusively affected by the offlineNonce property.
         */
        bool isOfflineRequest() const;
    };
    
    /**
     The HTTPRequestDataSignature structure contains result from HTTP request data signing
     operation.
     */
    struct HTTPRequestDataSignature
    {
        /**
         Version of PowerAuth protocol.
         */
        std::string version;
        /**
         Activation identifier received during the activation process.
         */
        std::string activationId;
        /**
         Application key copied from SessionSetup structure.
         */
        std::string applicationKey;
        /**
         NONCE used for the signature calculation.
         */
        std::string nonce;
        /**
         String representation of signature factor or combination of factors.
         */
        std::string factor;
        /**
         Calculated signature
         */
        std::string signature;
        
        /**
         Builds a value for "X-PowerAuth-Authorization" HTTP header.
         */
        std::string buildAuthHeaderValue() const;
    };
    
    /**
     The SignedData structure contains data and signature calculated from data.
     */
    struct SignedData
    {
        enum SigningKey
        {
            /**
             `KEY_SERVER_MASTER_PRIVATE` key was used for signature calculation
             */
            ECDSA_MasterServerKey = 0,
            /**
             `KEY_SERVER_PRIVATE` key was used for signature calculation
             */
            ECDSA_PersonalizedKey = 1
        };
        
        /**
         A key type used for signature calculation.
         */
        SigningKey signingKey;
        /**
         An arbitrary data
         */
        cc7::ByteArray data;
        /**
         A signagure calculated for data
         */
        cc7::ByteArray signature;
        
        /**
         Default constructor
         */
        SignedData(SigningKey signingKey = ECDSA_MasterServerKey) :
            signingKey(signingKey)
        {
        }
    };
    
    
    //
    // MARK: - Recovery Codes -
    //
    
    /**
     RecoveryData structure contains information about recovery code and PUK, created
     during the activation process.
     */
    struct RecoveryData
    {
        /**
         Contains recovery code.
         */
        std::string recoveryCode;
        /**
         Contains PUK, valid with recovery code.
         */
        std::string puk;
        
        /**
         Returns true if structure is empty (e.g. contains no recovery data)
         */
        bool isEmpty() const;
    };
    
    
    //
    // MARK: - Session activation steps -
    //
    
    /**
     Parameters for first step of device activation.
     */
    struct ActivationStep1Param
    {
        /**
         Full activation code. The value is optional for custom activations.
         */
        std::string activationCode;
        /**
         Signature calculated from activationCode.
         The value is optional in cases, when the user re-typed codes
         manually. If the value is available, then the Base64 string is expected.
         */
        std::string activationSignature;
    };
    
    /**
     Result from first step of device activation.
     */
    struct ActivationStep1Result
    {
        /**
         Device's public key, in Base64 format.
         */
        std::string devicePublicKey;
    };
    
    /**
     Parameters for second step of device activation.
     */
    struct ActivationStep2Param
    {
        /**
         Real Activation ID received from server.
         */
        std::string activationId;
        /**
         Server's public key, in Base64 format.
         */
        std::string serverPublicKey;
        /**
         Initial value for hash-based counter.
         */
        std::string ctrData;
        /**
         Data for activation recovery. May contain empty strings, in case
         that there's no recovery available.
         */
        RecoveryData activationRecovery;
    };
    
    /**
     Result from 2nd step of activation.
     */
    struct ActivationStep2Result
    {
        /**
         Short, human readable string, calculated from device's public key.
         You can display this code to the UI and user can confirm visually
         if the code is the same on both, server & client sides. This feature
         must be supported on the server's side of the activation flow.
         
         Note: The value is equivalent to H_K_DEVICE_PUBLIC mentioned in
         PowerAuth crypto protocol documentation.
         */
        std::string activationFingerprint;
    };
    
    
    
    //
    // MARK: - Activation status -
    //

    /**
     The EncryptedActivationStatus structure contains encrypted status
     data and parameters required for the data decryption.
     */
    struct EncryptedActivationStatus
    {
        /**
         The challenge value sent to the server. 16 bytes encoded to Base64 is expected.
         */
        std::string challenge;
        
        /**
         Contains encrypted status data. The Base64 encoded string is expected.
         */
        std::string encryptedStatusBlob;
        
        /**
         Contains nonce returned from the server. 16 bytes encoded to Base64 is expected.
         */
        std::string nonce;
    };
    
    /**
     The ActivationStatus structure represents complete status
     of the activation. The status is typically received
     as an encrypted blob and you can use Session to decode
     that blob into this structure.
     */
    struct ActivationStatus
    {
        /**
         The State enumeration defines all possible states of activation.
         The state is a part of information received together with the rest
         of the ActivationStatus structure. Don't misinterpret this enumeration
         as a session's internal state. These enumerations have complete different
         meanings.
         */
        enum State
        {
            Created         = 1,
            PendingCommit   = 2,
            Active          = 3,
            Blocked         = 4,
            Removed         = 5,
            // Deadlock is not received from the server.
            // The state is determined on client's side.
            Deadlock        = 128
        };
        
        /**
         The Version enumeration defines version of activation data, stored on the server.
         */
        enum Version
        {
            V2 = 2,             // PowerAuth Crypto V2
            V3 = 3,             // PowerAuth Crypto V3
            MaxSupported = V3,  // Max supported version defined by this SDK
        };
        
        /**
         The CounterState enumeration represents health of signature counter.
         */
        enum CounterState
        {
            // The state is not determined yet.
            Counter_NA = 0,
            // Counter is healthy, no additional action is required.
            Counter_OK,
            // Counter was just updated, so the session's persistent
            // data needs to be serialized.
            Counter_Updated,
            // The PowerAuth symmetric signature should be calculated
            // to preved counter's de-synchronization.
            Counter_CalculateSignature,
            // Counter is invalid and the activation is technically blocked.
            Counter_Invalid
        };
        
        /**
         State of the activation
         */
        State state;
        /**
         Health of signature counter.
         */
        CounterState counterState;
        /**
         Number of failed authentication attempts in a row.
         */
        cc7::U32 failCount;
        /**
         Maximum number of allowed failed authentication attempts in a row.
         */
        cc7::U32 maxFailCount;
        /**
         Current activation version stored on the server
         */
        cc7::byte currentVersion;
        /**
         If greater than `currentVersion`, then activation upgrade is available.
         */
        cc7::byte upgradeVersion;
        /**
         Look ahead window used on the server.
         */
        cc7::byte lookAheadCount;
        /**
         Least significant byte from counter.
         */
        cc7::byte ctrByte;
        /**
         Hash calculated from hash based counter.
         */
        cc7::ByteArray ctrDataHash;
        
        /**
         Constructs a new empty activation status structure.
         */
        ActivationStatus() :
            state(Created),
            counterState(Counter_NA),
            failCount(0),
            maxFailCount(0),
            currentVersion(0),
            upgradeVersion(0),
            lookAheadCount(0),
            ctrByte(0)
        {
        }
        
        /**
         Returns true if upgrade to a new activation data is possible.
         */
        bool isProtocolUpgradeAvailable() const;
        /**
         Returns true if dummy signature calculation is recommended to prevent
         the counter's de-synchronization.
         */
        bool isSignatureCalculationRecommended() const;
        /**
         Returns true if session's state should be serialized after the successful
         activation status decryption.
         */
        bool needsSerializeSessionState() const;
    };
    
    
    
    //
    // MARK: - End-To-End Encryption -
    //

    /**
     The ECIESEncryptorScope enumeration defines how ECIES encryptor is configured
     in Session.getEciesEncryptor() method.
     */
    enum ECIESEncryptorScope
    {
        /**
         An application scope means that encryptor can be constructed also when
         the session has no valid activation.
         */
        ECIES_ApplicationScope  = 0,
        /**
         An activation scope means that the encryptor can be constructed only when
         the session has a valid activation.
         */
        ECIES_ActivationScope   = 1
    };

    
    
    //
    // MARK: - Protocol upgrade -
    //
    
    struct ProtocolUpgradeData
    {
        struct V3
        {
            /**
             Data for new hash based counter. The Base64 string with 16 bytes
             of encoded data is expected.
             */
            std::string ctrData;
        };
        
        V3 toV3;
    };
    
} // io::getlime::powerAuth
} // io::getlime
} // io
