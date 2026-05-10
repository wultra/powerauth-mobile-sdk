/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PowerAuthHttpHeader.h"

/// The `PowerAuthEncryptorScope` enumeration defines how `PowerAuthEncryptor` encryptor
/// is configured.
typedef NS_ENUM(int, PowerAuthEncryptorScope) {
    /// An application scope means that encryptor can be constructed also when
    /// the session has no valid activation.
    PowerAuthEncryptorScope_Application = 1,
    /// An activation scope means that the encryptor can be constructed only when
    /// the session has a valid activation.
    PowerAuthEncryptorScope_Activation = 2,
};


/// The `PowerAuthEncryptedRequest` represents encrypted request.
@interface PowerAuthEncryptedRequest : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains request body.
@property (nonatomic, strong, readonly, nonnull) NSData* requestBody;
/// Contains request header that should be included in HTTP request.
///
/// - Note: You should not include the headers in case the request also contains header with
///         PowerAuth authentication code
@property (nonatomic, strong, readonly, nonnull) NSArray<PowerAuthHttpHeader*>* requestHeaders;

@end

/// The `PowerAuthEncryptedRequest` represents encrypted response received from the server.
@interface PowerAuthEncryptedResponse : NSObject

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



/// The `PowerAuthEncryptor` implement End-To-End Encryption in PowerAuth protocol.
/// The object can be used only once for request encryption and response decryption.
/// If you want to encrypt another request, then you have to construct a new encryptor.
@interface PowerAuthEncryptor : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains scope of created encryptor.
@property (nonatomic, readonly) PowerAuthEncryptorScope scope;

/// Contains YES if encryptor is ready for request encryption.
@property (nonatomic, readonly) BOOL canEncryptRequest;

/// Contains YES if encryptor is ready for response decryption.
@property (nonatomic, readonly) BOOL canDecryptResponse;

/// Encrypt request body.
/// - Parameters:
///   - requestBody: Data with request body to encrypt.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Encrypted request or `nil` in case of failure.
- (nullable PowerAuthEncryptedRequest*) encryptRequest:(nullable NSData*)requestBody
                                                 error:(NSError*_Nullable*_Nullable)error;
/// Decrypt response received from the server.
/// - Parameters:
///   - response: Object with received response.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Decrypted data or `nil` in case of failure.
- (nullable NSData*) decryptResponse:(nonnull PowerAuthEncryptedResponse*)response
                               error:(NSError*_Nullable*_Nullable)error;

@end
