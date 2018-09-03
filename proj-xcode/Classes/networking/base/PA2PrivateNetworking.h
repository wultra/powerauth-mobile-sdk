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

// This header imports all private classes used in our networking

#import "PA2Client.h"
#import "PA2PrivateMacros.h"
#import "PA2Log.h"

// Requests / Responses
#import "PA2CreateActivationRequest.h"
#import "PA2CreateActivationResponse.h"
#import "PA2DirectCreateActivationRequest.h"

#import "PA2ActivationStatusRequest.h"
#import "PA2ActivationStatusResponse.h"
#import "PA2VaultUnlockRequest.h"
#import "PA2VaultUnlockResponse.h"
#import "PA2EncryptedRequest.h"
#import "PA2EncryptedResponse.h"
#import "PA2GetTokenResponse.h"
#import "PA2RemoveTokenRequest.h"

// Private PA2Client interface...

@interface PA2Client (Private)

- (nonnull NSURLSessionDataTask*) createActivation:(nonnull PA2CreateActivationRequest*)request
										  callback:(nonnull void(^)(PA2RestResponseStatus status, PA2CreateActivationResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) getActivationStatus:(nonnull PA2ActivationStatusRequest*)request
											 callback:(nonnull void(^)(PA2RestResponseStatus status, PA2ActivationStatusResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) removeActivation:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
										  callback:(nonnull void(^)(PA2RestResponseStatus status, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) vaultUnlock:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
									  request:(nonnull PA2VaultUnlockRequest*)request
									 callback:(nonnull void(^)(PA2RestResponseStatus status, PA2VaultUnlockResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) createToken:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
								encryptedData:(nonnull PA2EncryptedRequest *)encryptedData
									 callback:(nonnull void(^)(PA2RestResponseStatus status, PA2EncryptedResponse * _Nullable response, NSError * _Nullable error))callback;

- (nonnull NSURLSessionDataTask*) removeToken:(nonnull PA2RemoveTokenRequest*)request
							  signatureHeader:(nonnull PA2AuthorizationHttpHeader*)signatureHeader
									 callback:(nonnull void(^)(PA2RestResponseStatus status, NSError * _Nullable error))callback;

@end
