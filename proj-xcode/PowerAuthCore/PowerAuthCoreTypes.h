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

#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreData.h>
#import <PowerAuthCore/PowerAuthCoreOtpUtil.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>


/**
 The PowerAuthCoreProtocolVersion enum defines PowerAuth protocol version. The main difference
 between V2 & V3 is that V3 is using hash-based counter instead of linear one,
 and all E2EE tasks are now implemented by ECIES.
 
 This version of SDK is supporting V2 protol in very limited scope, where only
 the V2 authorization code calculations are supported. Basically, you cannot connect
 to V2 servers with V3 SDK.
 */
typedef NS_ENUM(int, PowerAuthCoreProtocolVersion) {
    /**
     Protocol version is not specified, or cannot be determined.
     */
    PowerAuthCoreProtocolVersion_NA = 0,
    /**
     Protocol version 2
     */
    PowerAuthCoreProtocolVersion_V2 = 2,
    /**
     Protocol version 3
     */
    PowerAuthCoreProtocolVersion_V3 = 3,
    /**
     Protocol version 4
     */
    PowerAuthCoreProtocolVersion_V4 = 4,
};


/**
 The PowerAuthCoreHTTPRequestData object contains all data required for calculating signature from
 HTTP request. You have to provide values at least non-empty strings to `method` and `uri` 
 members, to pass a data validation.
 */
@interface PowerAuthCoreHTTPRequestData : NSObject

/**
 A whole POST body or data blob prepared in 'Session::prepareKeyValueMapForDataSigning'
 method. You can also calculate signature for an empty request with no body or without
 any GET parameters. In this case the member may be empty.
 */
@property (nonatomic, strong, nullable) NSData * body;
/**
 HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected)
 */
@property (nonatomic, strong, nonnull) NSString * method;
/**
 Relative URI of the request.
 */
@property (nonatomic, strong, nonnull) NSString * uri;
/**
 Optional, contains NONCE generated externally. The value should be used for offline data
 signing purposes only. The Base64 string is expected.
 */
@property (nonatomic, strong, nullable) NSString * offlineNonce;

/**
 Length of offline signature component. The values between 4 and 8 are allowed.
 The default value is 8.
 */
@property (nonatomic, assign) NSUInteger offlineSignatureSize;

@end


/**
 The PowerAuthCoreHTTPRequestDataSignature object contains result from HTTP request data signing
 operation.
 */
@interface PowerAuthCoreHTTPRequestDataSignature : NSObject

/**
 Version of PowerAuth protocol.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * version;
/**
 Activation identifier received during the activation process.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * activationId;
/**
 Application key copied from Session.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * applicationKey;
/**
 NONCE used for the offline authorization code calculation.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * nonce;
/**
 String representation of signature factor or combination of factors.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * factor;
/**
 Calculated signature
 */
@property (nonatomic, strong, nonnull, readonly) NSString * signature;
/**
 Contains a complete value for "X-PowerAuth-Authorization" HTTP header.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * authHeaderValue;

@end

/**
 The PowerAuthCoreSigningDataKey enumeration defines key type used for signature calculation.
 */
typedef NS_ENUM(int, PowerAuthCoreSigningDataKey) {
    /**
     `KEY_SERVER_MASTER_PRIVATE` key was used for signature calculation
     */
    PowerAuthCoreSigningDataKey_ECDSA_MasterServerKey = 0,
    /**
     `KEY_SERVER_PRIVATE` key was used for signature calculation
     */
    PowerAuthCoreSigningDataKey_ECDSA_PersonalizedKey = 1,
    /**
     `APP_SECRET` key is used for HMAC-SHA256 signature calculation.
     */
    PowerAuthCoreSigningDataKey_HMAC_Application = 2,
    /**
     `KEY_TRANSPORT` key is used for HMAC-SHA256 signature calculation.
     */
    PowerAuthCoreSigningDataKey_HMAC_Activation = 3
};

/**
 The `PowerAuthCoreSignatureFormat` enumeration defines signature type expected at input, or produced
 at output.
 */
typedef NS_ENUM(int, PowerAuthCoreSignatureFormat) {
    /**
     If used, then `PowerAuthCoreSignatureFormat_ECDSA_DER` is used for ECDSA signature.
     For the HMAC signature, the raw bytes is always used.
     */
    PowerAuthCoreSignatureFormat_Default = 0,
    /**
     ECDSA signature in DER format is expected at input, or produced at output:
     ```
     // ASN.1 notation:
     ECDSASignature ::= SEQUENCE {
         r   INTEGER,
         s   INTEGER
     }
     ```
     */
    PowerAuthCoreSignatureFormat_ECDSA_DER = 1,
    /**
     ECDSA signature in JOSE format is expected at input, or produced at output.
     */
    PowerAuthCoreSignatureFormat_ECDSA_JOSE = 2
};

/**
 The PowerAuthCoreSignedData object contains data and signature calculated from data.
 */
@interface PowerAuthCoreSignedData : NSObject
/**
 A signing key to use.
 */
@property (nonatomic, assign) PowerAuthCoreSigningDataKey signingDataKey;
/**
 A format of signature expected at input or produced at output.
 */
@property (nonatomic, assign) PowerAuthCoreSignatureFormat signatureFormat;
/**
 A data protected with signature
 */
@property (nonatomic, strong, nonnull) NSData * data;
/**
 A signagure calculated for data
 */
@property (nonatomic, strong, nonnull) NSData * signature;
/**
 A data protected with signature in Base64 format. The value is
 mapped to the `data` property.
 */
@property (nonatomic, strong, nonnull) NSString * dataBase64;
/**
 A signagure calculated for data in Base64 format. The value is
 mapped to the `signature` property.
 */
@property (nonatomic, strong, nonnull) NSString * signatureBase64;

@end


#pragma mark - Activation status -

/**
 The PowerAuthCoreActivationState enum defines all possible states of activation.
 The state is a part of information received together with the rest
 of the PowerAuthCoreActivationStatus object.
 */
typedef NS_ENUM(int, PowerAuthCoreActivationState) {
    /**
     The activation is just created.
     */
    PowerAuthCoreActivationState_Created  = 1,
    /**
     The activation is not completed yet on the server.
     */
    PowerAuthCoreActivationState_PendingCommit = 2,
    /**
     The shared secure context is valid and active.
     */
    PowerAuthCoreActivationState_Active   = 3,
    /**
     The activation is blocked.
     */
    PowerAuthCoreActivationState_Blocked  = 4,
    /**
     The activation doesn't exist anymore.
     */
    PowerAuthCoreActivationState_Removed  = 5,
    /**
     The activation is technically blocked. You cannot use it anymore
     for the authorization code calculations.
     */
    PowerAuthCoreActivationState_Deadlock   = 128,
};

/**
 The PowerAuthCoreActivationStatus object represents complete status of the activation.
 The status is typically received as an encrypted blob and you can use module
 to decode that blob into this object.
 */
@interface PowerAuthCoreActivationStatus : NSObject

/**
 State of the activation
 */
@property (nonatomic, assign, readonly) PowerAuthCoreActivationState state;
/**
 Number of failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 failCount;
/**
 Maximum number of allowed failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 maxFailCount;
/**
 Contains (maxFailCount - failCount) if state is `PowerAuthCoreActivationState_Active`,
 otherwise 0.
 */
@property (nonatomic, assign, readonly) UInt32 remainingAttempts;

// SDK-private (application should not use such interface)

/**
 Contains current version of activation
 */
@property (nonatomic, assign, readonly) UInt8 currentActivationVersion;
/**
 Contains version of activation available for upgrade.
 */
@property (nonatomic, assign, readonly) UInt8 upgradeActivationVersion;
/**
 Contains YES if upgrade to a newer protocol version is available.
 */
@property (nonatomic, assign, readonly) BOOL isProtocolUpgradeAvailable;
/**
 Returns true if dummy authorization code calculation is recommended to prevent
 the counter's de-synchronization.
 */
@property (nonatomic, assign, readonly) BOOL isSignatureCalculationRecommended;
/**
 Returns true if session's state should be serialized after the successful
 activation status decryption.
 */
@property (nonatomic, assign, readonly) BOOL needsSerializeSessionState;

@end

/// The `PowerAuthCoreEncryptorScope` enumeration defines how `PowerAuthCoreEncryptor` encryptor
/// is configured.
typedef NS_ENUM(int, PowerAuthCoreEncryptorScope) {
    /// No encryptor is specified in core request.
    PowerAuthCoreEncryptorScope_None = 0,
    /// An application scope means that encryptor can be constructed also when
    /// the session has no valid activation.
    PowerAuthCoreEncryptorScope_Application = 1,
    /// An activation scope means that the encryptor can be constructed only when
    /// the session has a valid activation.
    PowerAuthCoreEncryptorScope_Activation = 2,
};
