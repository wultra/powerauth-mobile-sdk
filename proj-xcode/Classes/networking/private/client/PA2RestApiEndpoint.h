/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2PrivateTypes.h"

/**
 The `PA2RestApiEndpoint` object describes the endpoint in PowerAuth REST API.
 The object contains all required properties for a proper HTTP request construction
 and for the response processing.
 */
@interface PA2RestApiEndpoint : NSObject

/// Relative path
@property (nonatomic, strong, readonly) NSString * relativePath;

/// HTTP method (currently only POST is supported)
@property (nonatomic, strong, readonly) NSString * method;

/// Encryptor's identifier, in case that request & response is encrypted.
@property (nonatomic, assign, readonly) PA2EncryptorId encryptor;

/// uriId for PowerAuth signature calculation, in case that request is signed.
@property (nonatomic, strong, readonly) NSString * authUriId;

/// Object type expected in request body.
/// Note that the request class is used only for an internal sanity checks
/// to validate, whether the request object has an expected type.
@property (nonatomic, strong, readonly) Class requestClass;

/// Object type expected in the response data.
@property (nonatomic, strong, readonly) Class responseClass;

/// Returns YES, if request needs to be processed in serialized queue.
@property (nonatomic, assign, readonly) BOOL isSerialized;

/// Returns YES, if request requires encryption
@property (nonatomic, assign, readonly) BOOL isEncrypted;

/// Returns YES, if request needs to be signed with PA signature
@property (nonatomic, assign, readonly) BOOL isSigned;

/// Returns YES, if endpoint is available during the protocol upgrade.
@property (nonatomic, assign, readonly) BOOL isAvailableInProtocolUpgrade;

#pragma mark - Endpoint construction

+ (instancetype) createActivation;
+ (instancetype) getActivationStatus;
+ (instancetype) removeActivation;

+ (instancetype) upgradeStartV3;
+ (instancetype) upgradeCommitV3;

+ (instancetype) validateSignature;
+ (instancetype) vaultUnlock;

+ (instancetype) getToken;
+ (instancetype) removeToken;

+ (instancetype) confirmRecoveryCode;

@end
