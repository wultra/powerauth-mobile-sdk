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

#import <PowerAuthCore/PowerAuthCoreTypes.h>

/// The `PowerAuthCoreAlgorithm` enumeration defines algorithms available for PowerAuth
/// initialization.
///
/// If you update `PowerAuthCoreAlgorithm`, then please change also `PowerAuthAlgorithm`.
typedef NS_ENUM(int, PowerAuthCoreAlgorithm) {
    /// Algorithm identifier for legacy protocol V3.3.
    PowerAuthCoreAlgorithm_LEGACY_P256 = 0,
    /// Algorithm identifier for V4 protocol, using only cryptography based on elliptic curves.
    PowerAuthCoreAlgorithm_EC_P384 = 1,
    /// Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
    /// elliptic curves.
    PowerAuthCoreAlgorithm_EC_P384_ML_L3 = 2,
    /// Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
    /// elliptic curves.
    PowerAuthCoreAlgorithm_EC_P384_ML_L5 = 3,
};

/// The `PowerAuthCoreConfig` object contains configuration for `PowerAuthCoreSession` object.
@interface PowerAuthCoreConfig : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains instance identifier provided in the configuration construction.
@property (nonatomic, strong, readonly, nonnull) NSString * instanceId;
/// Contains device specific data provided in the configuration construction.
@property (nonatomic, strong, readonly, nonnull) NSData * deviceSpecificData;
/// Contains algorithm provided in the configuration construction.
@property (nonatomic, readonly) PowerAuthCoreAlgorithm algorithm;

/// Create instance of `PowerAuthCoreConfig` object from the provided parameters.
///
/// - Parameters:
///   - configuration: SDK configuration string.
///   - deviceSpecificData: Device specific data.
///   - instanceId: Instance identifier.
///   - algorithm: Algorithm to use in the PowerAuth instance.
///   - error: Pointer to error. If provided, then contains reason of failure in case the construction fails.
///
/// - Returns: New instance of `PowerAuthCoreConfig` class or `nil` in case of failure.
+ (nullable PowerAuthCoreConfig*) buildWithConfiguration:(nonnull NSString*)configuration
                                      deviceSpecificData:(nonnull NSData*)deviceSpecificData
                                              instanceId:(nonnull NSString*)instanceId
                                               algorithm:(PowerAuthCoreAlgorithm)algorithm
                                                   error:(NSError*_Nullable*_Nullable)error;

/// Create a configuration using cached device-specific keys for possession protection.
/// - Parameters:
///   - configuration: SDK configuration string.
///   - deviceSpecificData: Device specific data used when a cached key is not supplied.
///   - possessionKeyV3: Optional 16-byte V3 key. If nil or empty, it is derived from device specific data.
///   - possessionKeyV4: Optional 32-byte V4 key. If nil or empty, it is derived from device specific data.
///   - instanceId: Instance identifier.
///   - algorithm: Algorithm to use in the PowerAuth instance.
///   - error: Pointer to receive the construction error.
/// - Returns: A configuration, or nil on failure.
+ (nullable PowerAuthCoreConfig*) buildWithConfiguration:(nonnull NSString*)configuration
                                      deviceSpecificData:(nonnull NSData*)deviceSpecificData
                                         possessionKeyV3:(nullable NSData*)possessionKeyV3
                                         possessionKeyV4:(nullable NSData*)possessionKeyV4
                                              instanceId:(nonnull NSString*)instanceId
                                               algorithm:(PowerAuthCoreAlgorithm)algorithm
                                                   error:(NSError*_Nullable*_Nullable)error;

/// Derive a device-specific key for possession protection, ready for persistent caching.
/// - Parameters:
///   - deviceSpecificData: Non-empty device specific data.
///   - protocolVersion: V3 or V4 protocol version.
///   - error: Pointer to receive the derivation error.
/// - Returns: A 16-byte V3 key or a 32-byte V4 key, or nil on failure.
+ (nullable NSData*) derivePossessionKeyFromDeviceSpecificData:(nonnull NSData*)deviceSpecificData
                                              protocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
                                                        error:(NSError*_Nullable*_Nullable)error;

/// Validate SDK configuration string.
/// - Parameters:
///   - configuration: SDK configuration string to validate.
///   - algorithm: Algorithm to use in the PowerAuth instance.
///   - error: Pointer to error. If provided, then contains reason of failure in case the validation fails.
/// - Returns: YES if configuration string is valid.
+ (BOOL) validateConfiguration:(nonnull NSString*)configuration
                     algorithm:(PowerAuthCoreAlgorithm)algorithm
                         error:(NSError*_Nullable*_Nullable)error;

@end
