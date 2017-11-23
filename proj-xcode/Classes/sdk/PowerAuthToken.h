/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

// Forward declarations...
@class PA2AuthorizationHttpHeader;
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
 Contains name of the token.
 The value may be nil in cases, that token instance has been already removed
 from the store.
 */
@property (nonatomic, strong, readonly, nullable) NSString * tokenName;
/**
 Contains weak reference to the token store.
 */
@property (nonatomic, weak, readonly, nullable) id<PowerAuthTokenStore> tokenStore;
/**
 Contains YES if this token's instance is valid (e.g. was not removed)
 */
@property (nonatomic, readonly) BOOL isValid;

/**
 Returns a new token-based authorization header or nil, if it's not possible to generate the header.
 */
- (nullable PA2AuthorizationHttpHeader*) generateHeader;

/**
 Returns YES if both token objects are equal.
 */
- (BOOL) isEqualToToken:(nonnull PowerAuthToken*)token;

@end


#pragma mark - Store -

/**
 The PowerAuthTokenStoreTask is an abstract type for token store task. The object type
 returned from store may vary between store implementations.
 */
typedef id PowerAuthTokenStoreTask;

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
 Provides an interface for creating access tokens.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens when token is locally present
 and available (e.g. doesn't need to be acquired from the server) or in case of error.
 */
- (nullable PowerAuthTokenStoreTask) requestAccessTokenWithName:(nonnull NSString*)name
												 authentication:(nonnull PowerAuthAuthentication*)authentication
													 completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion;

/**
 Removes a previously created access token from the server.
 
 Returns cancellable object if operation is asynchronous, or nil, when the completion
 block was executed synchronously. That typically happens in case of error.
 */
- (nullable PowerAuthTokenStoreTask) removeAccessTokenWithName:(nonnull NSString*)name
													completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion;

/**
 Cancels previously created store task. Note that cancelling may lead to inconsistent state, when the server will execute
 the operation but client application will not get the result.
 
 It is safe to call this method with nil task.
 */
- (void) cancelTask:(nullable PowerAuthTokenStoreTask)task;

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

@end
