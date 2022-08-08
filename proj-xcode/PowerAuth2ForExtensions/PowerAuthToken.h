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

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>
#import <PowerAuth2ForExtensions/PowerAuthOperationTask.h>

// Forward declarations...
@class PowerAuthAuthorizationHttpHeader;
@class PowerAuthAuthentication;
@protocol PowerAuthTokenStore;


#pragma mark - Token -

/**
 The `PowerAuthToken` interface generates a token based authorization headers.
 You have to use `PowerAuthTokenStore` to get an instance of this class.
 
 The whole interface is thread safe.
 */
@interface PowerAuthToken : NSObject<NSCopying>

/**
 Contains symbolic name of the token.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * tokenName;
/**
 Contains token's unique identifier. You normally don't need this value, but it may help
 with application's debugging. The value identifies this token on PowerAuth server.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * tokenIdentifier;

/**
 Contains weak reference to the token store.
 */
@property (nonatomic, weak, readonly, nullable) id<PowerAuthTokenStore> tokenStore;
/**
 Contains YES if this instance contains valid token data.
 */
@property (nonatomic, readonly) BOOL isValid;
/**
 Contans YES if this instance can generate a header. This is equivalent to
 `token.isValid && token.tokenStore.canRequestForAccessToken`
 */
@property (nonatomic, readonly) BOOL canGenerateHeader;

/**
 Returns a new token-based authorization header or nil, if it's not possible to generate the header.
 */
- (nullable PowerAuthAuthorizationHttpHeader*) generateHeader;

/**
 Returns YES if both token objects are equal.
 */
- (BOOL) isEqualToToken:(nonnull PowerAuthToken*)token;

@end


#pragma mark - Store -

/**
 The `PowerAuthTokenStore` protocol defines interface for creating access tokens.
 The implementing class must be thread safe. It is expected to access store
 from multiple threads.
 */
@protocol PowerAuthTokenStore
@required
/**
 The implementation must return YES if it's possible to create access tokens.
 */
- (BOOL) canRequestForAccessToken;

/**
 Create a new access token with given name for requested signature factors. The created token objects
 always contains valid token data.
 
 Discussion
 
 Note that the method is thread safe, but it's not recommended to request for the same token
 name in parallel when the token is not stored in local database yet. If the method returns
 an asynchronous task, then the pending HTTP request to the server has been issued, so you
 should not ask for the same token while the task is in processing. You can use `-hasLocalTokenWithName:`
 method to check, whether the token is already in the local database.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens when token is locally present
 and available (e.g. doesn't need to be acquired from the server) or in case of error.
 */
- (nullable id<PowerAuthOperationTask>) requestAccessTokenWithName:(nonnull NSString*)name
                                                    authentication:(nonnull PowerAuthAuthentication*)authentication
                                                        completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion;

/**
 Create a new access token with given name without needing an authentication object. The method
 is useful only on watchOS platform, when the token is being acquired from counterpart iOS application.
 In this case, it's expected that token is already cached on iPhone and therefore the authentication
 object is not required.
 
 On iOS, method always returns invalid parameter error.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens when token is locally present
 and available (e.g. doesn't need to be acquired from the server) or in case of error.
 */
- (nullable id<PowerAuthOperationTask>) requestAccessTokenWithName:(nonnull NSString*)name
                                                        completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion;

/**
 Removes previously created access token from the server and from local database.
 
 Note that if the removal request doesn't succeed, then the local token's data is not removed.
 The method is thread safe, but it's not recommended to issue conflicting request for the same
 token's name in parallel (e.g. create & remove token at the same time).
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens in case of error.
 */
- (nullable id<PowerAuthOperationTask>) removeAccessTokenWithName:(nonnull NSString*)name
                                                       completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion;

/**
 Cancels previously created store task. Note that cancelling may lead to inconsistent state,
 when the server will execute the operation but client application will not get the result.
 
 It is safe to call this method with nil task.
 
 This method is deprecated, because now you can call cancel directly on object returned from the asynchronous method.
 */
- (void) cancelTask:(nullable id)task PA2_DEPRECATED(1.7.0);

/**
 Removes token with given name from the local database. Be aware that this operation doesn't invalidate
 token on the server, it will only remove data associated to the token from the local database. It is recommended
 to use this method only as a fallback when online removal fails and you don't need to cary about existence
 of the token on the server.
 */
- (void) removeLocalTokenWithName:(nonnull NSString*)name;

/**
 Removes all stored tokens from the local database. Be aware that this operation doesn't invalidate
 token on the server, it will only remove data associated to the token from the local database. It is recommended
 to use this method only as a fallback when online removal fails and you don't need to cary about existence
 of the token on the server.
 */
- (void) removeAllLocalTokens;

/**
 Returns YES if store has token with given name in its local database.
 */
- (BOOL) hasLocalTokenWithName:(nonnull NSString*)name;

/**
 Returns token object with given name if it's alreadu in local database or nil.
 */
- (nullable PowerAuthToken*) localTokenWithName:(nonnull NSString*)name;

@end
