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

#import <PowerAuthCore/PowerAuthCoreRequest.h>


/// The `PowerAuthCoreEncryptedRequest` represents encrypted request.
@interface PowerAuthCoreEncryptedRequest : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains request body.
@property (nonatomic, strong, readonly, nonnull) NSData* requestBody;
/// Contains request header that should be included in HTTP request.
///
/// - Note: You should not include the headers in case the request also contains header with
///         PowerAuth authentication code
@property (nonatomic, strong, readonly, nonnull) NSArray<PowerAuthCoreHttpHeader*>* requestHeaders;

@end

/// The `PowerAuthCoreEncryptedRequest` represents encrypted response received from the server.
@interface PowerAuthCoreEncryptedResponse : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Construct response with JSON representation.
/// - Parameter jsonRepresentation: JSON representation.
///   - error: Pointer where the error will be stored in case of failure.
- (nullable instancetype) initWithJsonRepresentation:(nonnull NSDictionary*)jsonRepresentation
                                               error:(NSError*_Nullable*_Nullable)error;

/// Construct response with response body.
/// - Parameter responseBody: Data with response body.
///   - error: Pointer where the error will be stored in case of failure.
- (nullable instancetype) initWithResponseBody:(nonnull NSData*)responseBody
                                         error:(NSError*_Nullable*_Nullable)error;

@end



/// The `PowerAuthCoreEncryptor` implement End-To-End Encryption in PowerAuth protocol.
/// The object can be used only once for request encryption and response decryption.
/// If you want to encrypt another request, then you have to construct a new encryptor.
@interface PowerAuthCoreEncryptor : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains scope of created encryptor.
@property (nonatomic, readonly) PowerAuthCoreEncryptorScope scope;

/// Contains YES if encryptor is ready for request encryption.
@property (nonatomic, readonly) BOOL canEncryptRequest;

/// Contains YES if encryptor is ready for response decryption.
@property (nonatomic, readonly) BOOL canDecryptResponse;

/// Encrypt request body.
/// - Parameters:
///   - requestBody: Data with request body to encrypt.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Encrypted request or `nil` in case of failure.
- (nullable PowerAuthCoreEncryptedRequest*) encryptRequest:(nullable NSData*)requestBody
                                                     error:(NSError*_Nullable*_Nullable)error;
/// Decrypt response received from the server.
/// - Parameters:
///   - response: Object with received response.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Decrypted data or `nil` in case of failure.
- (nullable NSData*) decryptResponse:(nonnull PowerAuthCoreEncryptedResponse*)response
                               error:(NSError*_Nullable*_Nullable)error;

@end

/// The `PowerAuthCoreEncryptorFactory` is object that construct End-To-End encryptors for
/// general application purpose.
@interface PowerAuthCoreEncryptorFactory : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;


/// Create encryptor with given scope. If the temporary key for requested scope is not valid, then
/// error is reported.
/// - Parameters:
///   - scope: Scope of encryptor
///   - error: Pointer where the error is stored in case of failure.
/// - Returns: New instance of encryptor or `nil` in case of failure.
- (nullable PowerAuthCoreEncryptor*) createEncryptorWithScope:(PowerAuthCoreEncryptorScope)scope
                                                        error:(NSError*_Nullable*_Nullable)error;

/// Fetch temporary key for given scope from the server.
/// - Parameters:
///   - scope: Scope of temporary key.
///   - error: Pointer where the error is stored in case of failure.
/// - Returns: Core HTTP request or `nil` in case of failure.
- (nullable PowerAuthCoreRequest*) fetchTemporaryKeyForScope:(PowerAuthCoreEncryptorScope)scope
                                                       error:(NSError*_Nullable*_Nullable)error;

/// Get information whether there's already pending request for fetching temporary key from the server.
/// - Parameter scope: Scope of key.
/// - Returns: `YES` if there's pending request.
- (BOOL) hasPendingRequestForTemporaryKeyWithScope:(PowerAuthCoreEncryptorScope)scope;

/// Get information whether there's temporary key with requested scope.
/// - Parameter scope: Scope of temporary key.
/// - Returns: `YES` if temporary key is present and is still valid.
- (BOOL) hasTemporaryKeyForScope:(PowerAuthCoreEncryptorScope)scope;

@end
