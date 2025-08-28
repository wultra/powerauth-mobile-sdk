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

/// The `PowerAuthCoreHttpHeader` object represents HTTP header with its name and value.
@interface PowerAuthCoreHttpHeader : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains HTTP header name
@property (nonatomic, strong, readonly, nonnull) NSString * headerName;
/// Contains HTTP header value
@property (nonatomic, strong, readonly, nonnull) NSString * headerValue;

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
