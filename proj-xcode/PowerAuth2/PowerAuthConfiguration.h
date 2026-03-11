/**
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2/PowerAuthSharingConfiguration.h>

/// The `PowerAuthAlgorithm` enumeration defines algorithms available for PowerAuth
/// initialization. The algorithm specifies also the protocol version used for communication
/// with the server.
typedef NS_ENUM(NSInteger, PowerAuthAlgorithm) {
    /// Algorithm identifier for legacy protocol V3.3.
    ///
    /// If used in `PowerAuthConfiguration`, then the protocol upgrade is automatically disabled
    /// and instance of `PowerAuthSDK` will use legacy protocol only for communicating with the server.
    PowerAuthAlgorithm_LEGACY_P256 = 0,
    /// Algorithm identifier for V4 protocol, using only cryptography based on elliptic curves.
    /// The following algorithms are used:
    /// - Key agreement: ECDHE with P-384
    /// - Signatures: ECDSA with P-384
    PowerAuthAlgorithm_EC_P384 = 1,
    /// Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
    /// elliptic curves.
    /// The following algorithms are used:
    /// - Key agreement: ECDHE with P-384 combined with ML-KEM-768
    /// - Signatures: ECDSA with P-384 combined with ML-DSA-65
    PowerAuthAlgorithm_EC_P384_ML_L3 = 2,
    /// Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
    /// elliptic curves.
    /// The following algorithms are used:
    /// - Key agreement: ECDHE with P-384 combined with ML-KEM-1024
    /// - Signatures: ECDSA with P-384 combined with ML-DSA-87
    PowerAuthAlgorithm_EC_P384_ML_L5 = 3,
    
    /// Default algorithm. Value is identical to `PowerAuthAlgorithm_EC_P384_ML_L3`.
    PowerAuthAlgorithm_DEFAULT = PowerAuthAlgorithm_EC_P384_ML_L3
};


@class PowerAuthCoreData;

/// Class that represents a PowerAuthSDK instance configuration.
@interface PowerAuthConfiguration : NSObject<NSCopying>

/// No longer available. Use `init(instanceId:baseEndpointUrl:configuration:)` instead.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Initialize object with all required parameters.
/// - Parameters:
///   - instanceId: Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
///   - baseEndpointUrl: Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
///   - configuration: String with the cryptographic configuration.
///   - algorithm: PowerAuth algorithm selected for communication with the server.
- (nonnull instancetype) initWithInstanceId:(nonnull NSString*)instanceId
                            baseEndpointUrl:(nonnull NSString*)baseEndpointUrl
                              configuration:(nonnull NSString*)configuration
                                  algorithm:(PowerAuthAlgorithm)algorithm;

/// Initialize object with all required parameters.
/// - Parameters:
///   - instanceId: Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
///   - baseEndpointUrl: Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
///   - configuration: String with the cryptographic configuration.
- (nonnull instancetype) initWithInstanceId:(nonnull NSString*)instanceId
                            baseEndpointUrl:(nonnull NSString*)baseEndpointUrl
                              configuration:(nonnull NSString*)configuration;

/// Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
@property (nonatomic, strong, nonnull, readonly) NSString *instanceId;

/// Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
@property (nonatomic, strong, nonnull, readonly) NSString *baseEndpointUrl;

/// String with the cryptographic configuration.
@property (nonatomic, strong, nonnull, readonly) NSString *configuration;

/// This value specifies 'key' used to store this PowerAuthSDK instance biometry related key in the biometry key keychain.
@property (nonatomic, strong, nonnull) NSString *keychainKey_Biometry;

/// Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
/// @deprecated EEK is no longer used in SDK.
@property (nonatomic, strong, nullable) PowerAuthCoreData * externalEncryptionKey PA2_DEPRECATED(2.0);

/// Algorithm selected for communication with the server.
@property (nonatomic, assign) PowerAuthAlgorithm algorithm;

/**
 Property is deprecated and has no effect in PowerAuth Mobile SDK version 2.0+.
 */
@property (nonatomic, assign) BOOL disableAutomaticProtocolUpgrade PA2_DEPRECATED(2.0.0);

/**
 Length of offline authentication code component. The value between 4 and 8 is allowed.
 
 Default value is `8`.
 
 Property is deprecated, use `offlineAuthenticationCodeComponentLength` with the same functionality.
 */
@property (nonatomic, assign) NSUInteger offlineSignatureComponentLength PA2_DEPRECATED(2.0.0);

/**
 Length of offline authentication code component. The value between 4 and 8 is allowed.
 
 Default value is `8`.
 */
@property (nonatomic, assign) NSUInteger offlineAuthenticationCodeComponentLength;

/**
 If set, then this instance of PowerAuthSDK can be shared between multiple vendor applications.
 */
@property (nonatomic, strong, nullable) PowerAuthSharingConfiguration * sharingConfiguration;

/** Validate that the configuration is properly set (all required values were filled in).
 */
- (BOOL) validateConfiguration
            NS_SWIFT_NAME(validate());

@end
