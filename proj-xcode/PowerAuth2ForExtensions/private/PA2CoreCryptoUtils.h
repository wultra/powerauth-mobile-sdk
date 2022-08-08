/*
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

#import <Foundation/Foundation.h>

/**
 The PA2CoreCryptoUtils class provides several cryptographic primites
 normally available via PowerAuthCore module, for modules that must not
 depend on PowerAuthCore framework.
 */
@interface PA2CoreCryptoUtils : NSObject

/**
 Computes SHA-256 from given data.
 */
+ (nonnull NSData*) hashSha256:(nonnull NSData*)data;

/**
 Computes HMAC-SHA-256 for given data and key.
 */
+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data
                           key:(nonnull NSData*)key;

/**
 Generates a required amount of random bytes. Returns nil in case that
 underlying random generator is broken.
 */
+ (nullable NSData*) randomBytes:(NSUInteger)count;

@end
