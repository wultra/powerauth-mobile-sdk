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

typedef void(^PowerAuthCoreRequestCallback)(id _Nullable response, NSError * _Nullable error);

/// The `PowerAuthCoreRequest` object represents a HTTP request created in core module.
/// The object provide all
@interface PowerAuthCoreRequest : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains information whether this request require time synchronized with the server.
@property (nonatomic, readonly) BOOL isRequireSynchronizedTime;

/// Contains information whether this request require serial queue for its execution.
@property (nonatomic, readonly) BOOL isRequireSerialQueue;

/// Contains information whether this request is allowed during the protocol upgrade.
@property (nonatomic, readonly) BOOL isAllowedInUpgrade;

/// Contains scope of the temporary encryption key required for the request processing.
/// If `PowerAuthCoreEncryptorScope_None` is used, then request has no encryption.
@property (nonatomic, readonly) PowerAuthCoreEncryptorScope encryptorScope;

/// Contains information whether this request is authenticated with authentication header.
@property (nonatomic, readonly) BOOL isAuthenticated;

/// Contains relative path to endpoint.
@property (nonatomic, readonly, strong, nonnull) NSString* relativePath;

/// Contains HTTP method.
@property (nonatomic, readonly, strong, nonnull) NSString* httpMethod;

/// Contains HTTP request body. Be aware, that you have to call `prepareRequest()` method
/// to prepare the content of the body. If the request is not prepared, then contains `nil`
/// and `failure` property is updated with the error.
@property (nonatomic, readonly, strong, nonnull) NSData* requestBody;

/// Contains HTTP request body. Be aware, that you have to call `prepareRequest()` method
/// to prepare the headers. If the request is not prepared, then contains `nil` and `failure`
/// property is updated with the error.
@property (nonatomic, readonly, strong, nonnull) NSArray<PowerAuthCoreHttpHeader*>* requestHeaders;

/// Contains YES if the request is completed and successfully processed.
@property (nonatomic, readonly) BOOL isCompleted;

/// Contains YES if the request is finished no matter of the result. Use `isCompleted`,
/// `isCanceled` or `isFailed` to determine the exact result.
@property (nonatomic, readonly) BOOL isDone;
/// Contains YES if the request has been canceled.
@property (nonatomic, readonly) BOOL isCanceled;
/// Contains YES if the request processing failed.
@property (nonatomic, readonly) BOOL isFailed;

/// Contains last failure produced in the request object. For example, if you access
/// `requestBody` property
@property (nonatomic, readonly, strong, nullable) NSError* failure;

/// Contains response object if this kind of request provide some response object.
@property (nonatomic, readonly, strong, nullable) id responseObject;

/// Contains response in JSON representation.
@property (nonatomic, readonly, strong, nullable) id responseJson;

/// Cancel the request and release underlying resources. You have to call this method
/// when the operation is canceled by the application or when failure response is
/// received from the server.
///
/// - Returns: YES in case of success, or NO if internal cancelation failed.
///            Check `failure` property for more details.
- (BOOL) cancel;

/// Prepare request body and headers. It's recommended to call this method on background
/// execution queue to avoid main thread disruptions.
///
/// If execution of this function fails, then the function will notify all its listeners.
///
/// - Parameter error: Pointer to output error in case of failure.
/// - Returns: YES in case of success or NO in case of failure.
- (BOOL) prepareRequest:(NSError*_Nullable*_Nullable)error;

/// Process response received from the server. It's recommended to call this method on background
/// execution queue to avoid main thread disruptions.
///
/// Function also notify all its listeners about successful or failure result of the call.
///
/// - Note: Be aware that the method doesn't handle standard PowerAuth error response. You suppose
///         to call this method only if successful response is received from the server.
///
/// - Parameter response: Response data received from the server.
/// - Parameter error: Pointer to output error in case of failure.
/// - Returns: YES in case of success or NO in case of failure.
- (BOOL) processResponse:(nullable NSData*)response error:(NSError*_Nullable*_Nullable)error;

/// Acquire internal request's lock and execute the given block.
/// - Parameter operation: Operation to execute.
/// - Returns: Value returned from operation block.
- (nullable id) executeOperation:(id _Nullable (^_Nonnull)(void))operation;

/// Custom data associated to the request and response processing. The request and response processing
/// doesn't use this property, so it's up to higher layers of SDK how to use the property.
@property (nonatomic, strong, nullable) id customRequestData;

@end

