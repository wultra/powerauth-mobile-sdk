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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 The PA2PrivateTokenData is a model object keeping all information about
 the token.
 */
@interface PA2PrivateTokenData : NSObject<NSCopying>

#pragma mark - Properties

/**
 Name of the token.
 */
@property (nonatomic, strong, nonnull) NSString * name;
/**
 Token's identifier, received from the server.
 */
@property (nonatomic, strong, nonnull) NSString * identifier;
/**
 Token's secret, received from the server.
 */
@property (nonatomic, strong, nonnull) NSData * secret;
/**
 Identifier of activation associated with the token. If nil, then the serialized
 data is still in old format and needs to be upgraded.
 */
@property (nonatomic, strong, nullable) NSString * activationIdentifier;
/**
 Integer represents PowerAuth Symmetric Signature factors used for the token creation.
 If value is equal to 0, then the token was created in older SDKs than 1.7.0.
 */
@property (nonatomic, assign) NSInteger authenticationFactors;

#pragma mark - Compare

/**
 Returns YES if both tokens contains equal information.
 */
- (BOOL) isEqualToTokenData:(nullable PA2PrivateTokenData*)tokenData;

#pragma mark - Serialization

/**
 Contains YES if all instance properties contains a valid objects.
 */
@property (nonatomic, readonly) BOOL hasValidData;

/**
 Returns NSData object with serialized content of the object.
 */
- (nonnull NSData*)serializedData;
/**
 Returns new `PA2PrivateTokenData` instance if provided data contains previously serialized data,
 or nil in case of deserialization failure.
 */
+ (nullable PA2PrivateTokenData*) deserializeWithData:(nonnull NSData*)data;

@end
