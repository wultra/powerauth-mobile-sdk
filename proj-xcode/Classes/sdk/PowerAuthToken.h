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
@interface PowerAuthToken : NSObject
/**
 Contains name of the token.
 The value may be nil in cases, that token instance has been already removed
 from the store.
 */
@property (atomic, strong, readonly, nullable) NSString * tokenName;
/**
 Contains weak reference to the token store.
 */
@property (atomic, weak, readonly, nullable) id<PowerAuthTokenStore> tokenStore;
/**
 Contains YES if this token's instance is valid (e.g. was not removed)
 */
@property (atomic, readonly) BOOL isValid;

/**
 Returns a new token-based authorization header or nil, if it's not possible to generate the header.
 */
- (nullable PA2AuthorizationHttpHeader*) generateHeader;

/**
 Removes token from associated token store and invalidates this instance.
 Note that if you call remove on one token's instance, it will not invalidate all other
 instances created for the same token's name.
 */
- (void) remove;

@end


#pragma mark - Store -

/**
 The PowerAuthTokenStoreTask is an abstract type for token store task. The object type
 returned from store may vary between store implementations.
 */
typedef id PowerAuthTokenStoreTask;

/**
 The `PowerAuthTokenStore` protocol defines interface for creating access tokens.
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
 block was executed synchronously. That typically happens when token is local and available
 (e.g. doesn't need to be acquired from the server) or in case of error.
 */
- (nullable PowerAuthTokenStoreTask) requestAccessTokenWithName:(nonnull NSString*)name
												 authentication:(nonnull PowerAuthAuthentication*)authentication
													 completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion;
/**
 Cancels previously created store task.
 It is safe to call this method with nil as task.
 */
- (void) cancelTask:(nullable PowerAuthTokenStoreTask)task;

/**
 Removes token with given name from the store.
 Note that you can use `token.remove()` to do the same thing.
 */
- (void) removeTokenWithName:(nonnull NSString*)name;

/**
 Removes all tokens stored in this token store.
 */
- (void) removeAllTokens;

@end
