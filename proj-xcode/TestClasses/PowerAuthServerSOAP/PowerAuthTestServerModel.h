/**
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

#import <Foundation/Foundation.h>

#pragma mark - System status

@interface PATSSystemStatus : NSObject

@property (nonatomic, strong) NSString * status;
@property (nonatomic, strong) NSString * applicationName;
@property (nonatomic, strong) NSString * applicationDisplayName;
@property (nonatomic, strong) NSString * applicationEnvironment;
@property (nonatomic, strong) NSString * timestamp;
@property (nonatomic, strong) NSString * version;

@end

#pragma mark - Application related

@interface PATSApplication : NSObject

@property (nonatomic, strong) NSString * applicationId;
@property (nonatomic, strong) NSString * applicationName;

@end

@interface PATSApplicationVersion : NSObject

@property (nonatomic, strong) NSString * applicationVersionId;
@property (nonatomic, strong) NSString * applicationVersionName;
@property (nonatomic, strong) NSString * applicationKey;
@property (nonatomic, strong) NSString * applicationSecret;
@property (nonatomic, assign) BOOL supported;

@end

@interface PATSApplicationVersionSupport : NSObject

@property (nonatomic, strong) NSString * applicationVersionId;
@property (nonatomic, assign) BOOL supported;

@end

@interface PATSApplicationDetail : PATSApplication

@property (nonatomic, strong) NSString * masterPublicKey;
@property (nonatomic, strong) NSArray<PATSApplicationVersion*> * versions;

@end


#pragma mark - Activation

@interface PATSInitActivationResponse : NSObject

@property (nonatomic, strong) NSString * activationId;
@property (nonatomic, strong) NSString * activationIdShort;
@property (nonatomic, strong) NSString * activationOTP;
@property (nonatomic, strong) NSString * activationCode;
@property (nonatomic, strong) NSString * activationSignature;
@property (nonatomic, strong) NSString * userId;
@property (nonatomic, strong) NSString * applicationId;

- (NSString*) activationCodeWithSignature;
- (NSString*) activationCodeWithoutSignature;

@end

@interface PATSCommitActivationResponse : NSObject

@property (nonatomic, strong) NSString * activationId;
@property (nonatomic, assign) BOOL activated;

@end


typedef enum _PATSActivationStatusEnum {
	// "unknown" must be defined, tests expects that 0 is not a valid state.
	PATSActivationStatus_Unknown,
	PATSActivationStatus_CREATED,
	PATSActivationStatus_OTP_USED,
	PATSActivationStatus_ACTIVE,
	PATSActivationStatus_BLOCKED,
	PATSActivationStatus_REMOVED,
} PATSActivationStatusEnum;

@interface PATSSimpleActivationStatus : NSObject

@property (nonatomic, strong) NSString * activationId;
@property (nonatomic, strong) NSString * activationStatus;
@property (nonatomic, assign) PATSActivationStatusEnum activationStatusEnum;

@end

@interface PATSActivationStatus : PATSSimpleActivationStatus

@property (nonatomic, strong) NSString * activationName;
@property (nonatomic, strong) NSString * userId;
@property (nonatomic, strong) NSString * applicationId;
@property (nonatomic, strong) NSString * timestampCreated;
@property (nonatomic, strong) NSString * timestampLastUsed;
@property (nonatomic, strong) NSString * encryptedStatusBlob;
@property (nonatomic, strong) NSString * devicePublicKeyFingerprint;
@property (nonatomic, assign) NSInteger protocolVersion;

@end

@interface PATSEncryptionKey : NSObject

@property (nonatomic, strong) NSString * applicationKey;
@property (nonatomic, strong) NSString * applicationId;
@property (nonatomic, strong) NSString * encryptionKey;
@property (nonatomic, strong) NSString * encryptionKeyIndex;
@property (nonatomic, strong) NSString * ephemeralPublicKey;

@end

#pragma mark - Signatures

@interface PATSVerifySignatureResponse : NSObject

@property (nonatomic, strong) NSString * activationId;
@property (nonatomic, strong) NSString * userId;
@property (nonatomic, strong) NSString * activationStatus;
@property (nonatomic, assign) PATSActivationStatusEnum activationStatusEnum;
@property (nonatomic, assign) NSInteger remainingAttempts;
@property (nonatomic, assign) BOOL signatureValid;

@end

@interface PATSOfflineSignaturePayload : NSObject

@property (nonatomic, strong) NSString * offlineData;
@property (nonatomic, strong) NSString * nonce;
// Attributes parsed from offlineData
@property (nonatomic, strong, readonly) NSString * parsedData;
@property (nonatomic, strong, readonly) NSString * parsedNonce;
@property (nonatomic, strong, readonly) NSString * parsedSigningKey;
@property (nonatomic, strong, readonly) NSString * parsedSignature;
@property (nonatomic, strong, readonly) NSString * parsedSignedData;

@end

#pragma mark - Token

@interface PATSToken : NSObject

@property (nonatomic, strong) NSString * tokenIdentifier;
@property (nonatomic, strong) NSString * tokenSecret;
@property (nonatomic, strong) NSString * activationId;

@end

@interface PATSTokenValidationRequest : NSObject

@property (nonatomic, strong) NSString * tokenIdentifier;
@property (nonatomic, strong) NSString * tokenDigest;
@property (nonatomic, strong) NSString * nonce;
@property (nonatomic, strong) NSString * timestamp;	// must be correctly converted

@end

@interface PATSTokenValidationResponse : NSObject

@property (nonatomic, assign) BOOL tokenValid;
@property (nonatomic, strong) NSString * activationId;
@property (nonatomic, strong) NSString * userId;
@property (nonatomic, strong) NSString * applicationId;
@property (nonatomic, strong) NSString * signatureType;

@end


#pragma mark - ECIES helper object

@interface PATSECIESCryptogram: NSObject

@property (nonatomic, strong) NSString * encryptedData;
@property (nonatomic, strong) NSString * mac;
@property (nonatomic, strong) NSString * ephemeralPublicKey;

@end

